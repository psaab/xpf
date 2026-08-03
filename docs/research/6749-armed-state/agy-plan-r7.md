### Evidence & Tool-Call Exemption Confirmation
* **Tool Call Status**: ZERO tool calls made (all tool calls auto-denied by environment constraint).
* **Evidence Source**: All analysis was conducted strictly against the inline v8 plan document (`docs/research/6749-armed-state/plan.md @ ee2f548d8`) and the verbatim source code excerpts provided in the prompt (`status.rs`, `planning.rs`, `snapshot.rs`, `rebind.rs`, `forwarding.rs`, `mod.rs`, `refresh_bindings.rs`, `bringup.rs`, `manager_ha.go`, `manager_worker_arm_5134.go`, `process_linkcycle.go`, `daemon_apply_dataplane.go`).
* **Sufficient / Desired Evidence**: The pasted inline evidence provided full visibility into the coordinator worker bring-up, status refresh, manager desired-state loop, link cycle flow, and daemon apply ordering. The only area where additional inline context would have been helpful is the exact definition of `d.hasMACDebt()` or `d.recordDataplaneWorkerArmDebt()` inside `pkg/daemon/daemon.go` to inspect how `Manager` and `Daemon` share MAC debt state during `NotifyLinkCycle()`.

---

### Section 1: Audit of Round-6 Folds in v7.1 / v8 Table

Reviewing the §1 disposition table against the v8 text and source excerpts:
1. **AGY f1 (Signature + Latch Atomicity)**: **CORRECTLY FOLDED.** `reconcile_status_bindings(state, defer_completion_authorized: bool)` isolates completion authorization to the tagged rebind caller. Latch consumption occurs inside the critical section on `Ok(())` before write-back/persist.
2. **AGY f2 / Codex f8 (MAC Debt Phase Revalidation)**: **CORRECTLY FOLDED in design, but exposed at invocation (see Finding 1).** The two-phase revalidation (MAC installed AND link up) with autonomous backoff and edge Warns prevents premature worker bring-up on partially-programmed interfaces.
3. **AGY f3 / Codex f7 (Retry Backoff & Predicate)**: **CORRECTLY FOLDED.** Backoff (5/10/20/60s cap with jitter), ~12 attempt cap, fingerprint edge Warn, and reset on pending-set/config/link changes prevent worker thrashing while preserving auto-healing.
4. **AGY f4 / Codex f6 (Clear-to-Dispatch / Defer Epoch)**: **CORRECTLY FOLDED.** Extending the Go defer flag across MAC programming, the 1s mlx5 quiescence sleep, and the tagged rebind round-trip prevents arm-sync or generic retries from recreating workers mid-quiescence.
5. **Codex f2 (C2 Result-Based & Claim Deletion)**: **CORRECTLY FOLDED.** Result-based C2 (`!armed || !registered` -> `operator`) removes the need for a wire discriminator. Candidate deletion destroying operator claims is cleanly bounded and documented in §10.
6. **Codex f3 (Volatile Refresh Identity Check)**: **CORRECTLY FOLDED.** `copy_live_snapshot` checks `socket_ifindex == binding.ifindex && socket_queue_id == binding.queue_id`, preventing cross-binding volatile state aliasing across failure restorations or defer windows.
7. **Codex f4/f5 (Projection-Scoped `update_fabrics` & Guard)**: **CORRECTLY FOLDED.** Splitting telemetry vs. projection, marking physical changes `pending`, rate-capping reconciles (≥2s), and adding the empty-replan guard prevents telemetry churn from triggering replans or sysfs-failure vector erasures.

---

### Section 2: Attack Surface Evaluation (Questions 1–8)

#### 1. Tri-State + Boundary Completeness (Open Q1)
* **Analysis**: Traced all status transition paths: initial creation (S1/S5 -> `pending`), defer applies (S3 -> `pending`), bring-up failures (S4' -> `pending`), interface flaps (S2 -> `pending`), operator verbs (C2 -> `operator`), successful armed reconcile (C1 -> `none`), and global fan-out (C3 -> `none`).
* **Conclusion**: There is **no path** to `Registered && !Armed && state == none` that is not global-fan-out created (`set_forwarding_state(false)`) or carried from a global disarm via R3. The state space is closed and complete.

#### 2. Tagged vs. Generic Retry Overlap (Open Q2)
* **Analysis**: If a NON-defer pending slot (e.g., prior S4' bring-up failure on interface X) exists when a tagged rebind completes for a deferred apply on interface Y, `complete_deferred = true` authorizes convergence of **all** registered `pending` slots in the current plan.
* **Conclusion**: **Acceptable and correct.** The `rebind` handler reconciles the entire binding plan for the accepted snapshot. If `afxdp.reconcile` succeeds for the whole plan, interface X's XSK sockets have been successfully bound alongside interface Y's. Holding X in a disarmed state after its worker successfully bound during a full-plan rebind would be incorrect.

#### 3. Volatile Identity Check vs. Multi-Queue Workers (Open Q3)
* **Analysis**: Inspected `refresh_bindings.rs:20-65` and `bringup.rs:265-290`. `coord.workers.live` is a `BTreeMap<u32, Arc<BindingLiveState>>` keyed by `slot` (`u32`). Every slot gets its own distinct `BindingLiveState` instance containing its specific `socket_ifindex` and `socket_queue_id`.
* **Conclusion**: `snap.socket_ifindex == binding.ifindex && snap.socket_queue_id == binding.queue_id` is per-slot exact. Live records of different slots (even on the same worker thread) carry distinct `socket_queue_id` values and will not cross-alias.

#### 4. Empty-Replan Guard Discriminator (Open Q4)
* **Analysis**: Evaluated distinguishing legitimate operator interface removals from sysfs read failures (`rx_queues == 0`).
* **Conclusion**: **Implementable directly from `snapshot` + replan output.** An intentional full removal results in `snapshot` containing zero zoned interface candidates (`snapshot_has_candidates(snapshot) == false`). A sysfs failure results in `snapshot` containing candidate definitions whose queue resolution returned 0. Comparing candidate presence in `snapshot` against the replan result provides an exact discriminator without needing per-record `rx_queues` provenance.

#### 5. Cumulative Blast-Radius (Open Q5)
* **Conclusion**: **REJECT SPLITTING.** The PR must remain unified. S3/S4'/S5 mark non-forwarding slots `pending`, the completion epoch prevents premature arming, daemon MAC debt handles netlink/quiescence retries, and the Go pending-activation retry guarantees autonomous convergence. Removing any single component leaves an open vector for an unarmed slot to disable the dataplane indefinitely.

#### 6. Test Plan Audit (Open Q7)
* **Analysis**: The test plan (§9 items 12–19 + Go tests) covers expansion while armed, deferred expansion, bring-up failures, operator overrides, coherent vector restoration, MAC debt, and `update_fabrics`.
* **Conclusion**: Comprehensive, but requires one explicit addition noted in Finding 2 below (`NotifyLinkCycle` behavior during active MAC debt).

#### 7. New Hazards in v8 vs. Master (Open Q8)
* **Conclusion**: No new hazards introduced. The projection-scoped `update_fabrics` fix closes the wrong-physical hazard introduced in v7, the Go shadow-latch clear prevents re-latching on snapshot republishes, and the 2s rate-cap prevents netlink flap thrashing.

---

### Section 3: Numbered Findings

#### Finding 1 [MAJOR]: `NotifyLinkCycle` missing MAC-debt context can authorize convergence during active MAC failures
* **File:Line Reference**: `pkg/dataplane/userspace/process_linkcycle.go:175-220` & `pkg/daemon/daemon_apply_dataplane.go:390-402`
* **Description**: In §5-C, v8 specifies that `ControlRequest{Type: "rebind", CompleteDeferred: true}` must only be sent when the link cycle followed a *successful* (both-phase) MAC program. However, `NotifyLinkCycle()` in `process_linkcycle.go:175` takes no parameters and currently issues `ControlRequest{Type: "rebind"}` without checking MAC programming outcome. If an un-related link cycle (e.g., netlink event or link flap) or a caller in `daemon_apply_dataplane.go` invokes `NotifyLinkCycle()` while `programRethMAC` has failed (active MAC debt), `NotifyLinkCycle` setting `CompleteDeferred = true` will clear the defer latch in the helper and arm new slots prematurely while the MAC is incorrect.
* **Remediation**: `NotifyLinkCycle` (or `Manager.rebindLocked`) must explicitly inspect manager/daemon MAC debt state (`!m.hasActiveMACDebt()`) before setting `CompleteDeferred: true` on the `ControlRequest`.

#### Finding 2 [MINOR]: Missing test case in §9 for `NotifyLinkCycle` under active MAC debt
* **File:Line Reference**: `docs/research/6749-armed-state/plan.md:950-985` (§9 Test Plan)
* **Description**: While §9 covers deferred expansion completion shapes and MAC debt retries, it does not explicitly pin the negative case where `NotifyLinkCycle` fires while MAC debt is active.
* **Remediation**: Add a Go unit test verifying that calling `NotifyLinkCycle()` while `pendingMACDebt == true` issues `ControlRequest{Type: "rebind", CompleteDeferred: false}`.

#### Finding 3 [NIT]: Explicit `m.deferWorkers` gate required in `syncDesiredForwardingStateLocked`
* **File:Line Reference**: `pkg/dataplane/userspace/manager_ha.go:601-610`
* **Description**: In master code `manager_ha.go:601`, `syncDesiredForwardingStateLocked` checks `m.lastStatus.ForwardingArmed == desired`. During a deferred apply, `m.lastStatus.ForwardingArmed` may be `false` (or helper bindings unarmed), causing `syncDesiredForwardingStateLocked` to send `set_forwarding_state(armed=true)` on periodic status ticks if not gated. §5-C mentions gating arm-sync on the defer flag, but `manager_ha.go:601` should explicitly list `if m.deferWorkers { return nil }` at entry.

---

### Final Verdict

PLAN-READY-WITH-NITS
