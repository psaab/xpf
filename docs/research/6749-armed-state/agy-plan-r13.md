# AGY plan review — round 13 — #6749 armed-state plan v8.8 (c2147e57329e)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence constraint; prompt /tmp/agy-6749-r13-prompt.txt assembled at 126,383 bytes). Raw output: /tmp/agy-6749-r13.out.

**Verdict: DEMAND-REVISION** (4 BLOCKER + 2 MAJOR).

---

### Adversarial PLAN Review (Round 13) — xpf issue #6749 (v8.8 Model)

---

### Key Findings

#### 1. [BLOCKER] Content-dedup collapse permanently desynchronizes Go (`acceptedConfigEpoch`) and helper (`stored config_epoch`), wedging adoption, latch echo, and fabric fences
- **Evidence / Location**: Plan doc §5-C (iii) / (iv) / (v), `process_status.go:72-80`, `builder.go:156-178`
- **Impact**: When a staged config's forwarding content matches the active config, Go executes a content-dedup skip (`process_status.go:72-80`) and collapses `m.acceptedConfigEpoch = m.pendingConfigEpoch` (e.g., advancing from epoch 4 to 5) without sending an `apply_snapshot` RPC to the helper. The helper's stored snapshot retains `config_epoch = 4`.
  - In all subsequent status polls, the helper echoes `status.config_epoch = 4`.
  - Go’s adoption gate (`status.config_epoch == m.acceptedConfigEpoch`) evaluates `4 == 5` (false) permanently.
  - The latch echo gate (`status.config_epoch == m.acceptedConfigEpoch`) evaluates `4 == 5` (false) permanently.
  - Any subsequent `update_fabrics` carrying `expected_config_epoch = 5` is REFUSED by the helper (`5 != 4`).
- **Correction**: The content-dedup skip must either update the helper's stored `config_epoch` via a lightweight control call or must NOT collapse `acceptedConfigEpoch` in Go without helper notification.

---

#### 2. [BLOCKER] Wire `config_epoch` stamping vs acceptance-minting rule creates an unresolvable contradiction
- **Evidence / Location**: Plan doc §5-C epoch contract & §6 wire protocol, `manager_compile.go:326-365`
- **Impact**: Plan v8.8 states that `m.pendingConfigEpoch` mints *once* at compile ACCEPTANCE (after observing a successful helper response, `manager_compile.go:361`). However, `publishSnapshot` (`manager_compile.go:342`) requires `snap.config_epoch` to be stamped on the wire before the RPC is dispatched:
  1. If `snap.config_epoch` uses the un-minted scalar (the prior accepted epoch), then two distinct compiled configs (A and B) travel on the wire with the *same* epoch, bypassing request-side fencing.
  2. If `m.pendingConfigEpoch` is incremented *before* dispatch, a failed publish leaves `m.pendingConfigEpoch` incremented without acceptance, violating the directive that failed compiles *never* mint an epoch.

---

#### 3. [BLOCKER] Defer-intent deletion during snapshot construction reopens the pre-MAC activation race
- **Evidence / Location**: Plan doc §5-C defer-intent atomicity, `manager_compile.go:200-229`
- **Impact**: Deleting the daemon’s pre-Compile `SetDeferWorkers(true)` call and deferring intent assignment to inside `Compile` under `m.mu` leaves `m.deferWorkers == false` while `Compile` builds the snapshot outside `m.mu` (`manager_compile.go:200-229`). If a status tick or event fires mid-compile, the arm-sync gate (`if desired && m.deferWorkers { return nil }`) fails to trigger because `m.deferWorkers` is still `false`. The arm-sync then issues an un-deferred arm/rebind against the old snapshot while the new MAC-changing snapshot is being built, recreating the `EBUSY` race condition.

---

#### 4. [BLOCKER] Deadlock vulnerability (`applySem` vs `m.mu`) between daemon debt attempts and manager re-applies
- **Evidence / Location**: Plan doc §5-C debt execution ownership, `controllers.go:112-132`, `daemon.go:485-496`
- **Impact**: Debt attempts execute daemon-side acquiring `applySem` first and then calling `ReportMACDebtAttempt` / `ValidateMACDebtEpoch` which acquire `m.mu` (`applySem > m.mu`). Conversely, manager-driven flows (such as `reapplyAfterDeferredMAC`, `publishSnapshotFailClosedLocked`, or `SetFabricForwarding`) hold `m.mu` while making IPC or daemon calls that acquire or block on `applySem`. Holding `m.mu` while waiting for `applySem` creates a classic AB-BA lock inversion.

---

#### 5. [MAJOR] Unbounded 1Hz dataplane disable oscillation under sysfs flap
- **Evidence / Location**: Plan doc §5-C (i) pre-disable & §9 test item 19(vii)
- **Impact**: On a 1Hz sysfs flap on a parent interface, `guard_env_generation` bumps every second. The status poll observes the bump and immediately dispatches `SyncFabricState`, which executes the pre-disable (`ctrl.Enabled = 0`). Because sysfs flaps continuously every second, `ctrl.Enabled` is continuously set to 0 once per second, periodically dropping dataplane traffic indefinitely.

---

#### 6. [MAJOR] Incomplete binding state reconciliation following late `macAndLinkRecovery` completion
- **Evidence / Location**: Plan doc §5-C debt lifecycle & §6 LinkController interface
- **Impact**: When a down bucket-i member transfers to `macAndLinkRecovery`, `macEpochDebt` clears and helper arming runs with that member un-bound/down. When the link returns later, `macAndLinkRecovery` re-drives netlink setup and XSK rebind daemon-side. However, v8.8 specifies no mechanism for the daemon to notify Go to update `activation_state` to `none` and trigger an armed reconcile for those specific slots once recovery completes.

---

### §1 Disposition Table Audit

- **Codex f2 / AGY f2 / SMR12-1 Row**: Claimed CLOSED by introducing `config_epoch` on the wire. **AUDIT FAILED** — as shown in Findings 1 and 2, the interaction between content-dedup skips and pre-acceptance wire stamping breaks epoch alignment and creates fence bypasses.

---

### Additional Evidence Desired

1. **Verbatim `process_status.go:72-80`**: Full implementation of the content-dedup skip path to inspect exact state mutations during skip decisions.
2. **Verbatim `manager_compile.go:200-239` & `:326-365`**: Full locking and snapshot construction logic to verify lock scopes across snapshot generation and RPC dispatch.
3. **Verbatim `daemon_ha_fabric.go`**: Retry scheduler and fabric debt data structures to evaluate sync debt clearing semantics.

---

DEMAND-REVISION
