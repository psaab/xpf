### Missing Evidence & Context Requests
Review was conducted strictly against the pasted v7 plan document and inline source excerpts. Additional code visibility would have been beneficial in two specific areas:
1. **`pkg/daemon/daemon_apply_dataplane.go:200-246`**: To inspect the exact execution flow of `programRethMAC`, error handling wrappers, and whether any daemon-internal netlink retry exists before returning to `ApplyConfig`.
2. **`pkg/dataplane/userspace/process_status.go:230-260`**: To inspect the exact lock acquisition structure around `m.mu`, `syncDesiredForwardingStateLocked`, and the proposed `lastPendingActivationRetry` check in the periodic status loop.

---

### Findings

#### 1. `userspace-dp/src/server/helpers/status.rs:373` & `userspace-dp/src/server/handlers/rebind.rs:42-76` — `reconcile_status_bindings` signature missing `complete_deferred` provenance; un-atomic latch consumption [BLOCKER]
- **Evidence**: `status.rs:373` defines `pub(crate) fn reconcile_status_bindings(state: &mut ServerState) -> Result<(), afxdp::ReconcileError>`. It accepts no request context or `complete_deferred` boolean.
- **Analysis**: §5-C states that activation convergence inside `reconcile_status_bindings` is gated on `!stored_defer || complete_deferred`, and that a successful tagged `rebind` consumes the stored latch (`defer_workers = false`). 
  - If `rebind.rs` clears `guard.snapshot.defer_workers = false` *before* calling `reconcile_status_bindings(guard)`, a post-teardown bring-up failure (S4') permanently consumes the defer latch on a failed operation.
  - If `rebind.rs` clears `guard.snapshot.defer_workers = false` *after* `reconcile_status_bindings(guard)` succeeds, then *during* `reconcile_status_bindings`, `guard.snapshot.defer_workers` is still `true`. Because `reconcile_status_bindings` has no parameter to know the caller passed `complete_deferred: true`, it evaluates `stored_defer == true` and **blocks convergence during the tagged rebind itself**.
- **Fix**: Explicitly thread `complete_deferred: bool` into `reconcile_status_bindings` (or pass a `ReconcileOptions` struct), and consume the snapshot latch inside `reconcile_status_bindings` atomically upon `reconcile()` returning `Ok(())` before status refresh/persistence.

#### 2. `pkg/daemon/daemon_apply_dataplane.go:247-270` & `393-401` — Transient MAC programming failure strands box in defer indefinitely [MAJOR]
- **Evidence**: `daemon_apply_dataplane.go:247-270` logs a warning when `programRethMAC` fails. In v7, completion dispatch (`reapplyAfterDeferredMAC` / `NotifyLinkCycle`) is suppressed on MAC failure.
- **Analysis**: When `programRethMAC` fails (e.g. transient netlink buffer overflow or interface busy), completion is skipped and `deferWorkersActive` stays `true`. Because `m.deferWorkers` remains set in Go, the Go pending-activation retry (`if desired == true && !m.deferWorkers`) suppresses plain rebinds. With no completion re-apply scheduled and no MAC retry debt recorded (unlike `#5134` worker arm debt), no background loop in Go or the helper will ever retry. The box is stranded in defer (`ctrl.Enabled = 0`, pending slots) indefinitely until an un-related future commit or operator event occurs.
- **Fix**: The daemon must record a MAC programming debt (or schedule daemon-side MAC retries on status ticks) when `programRethMAC` fails, re-driving MAC programming and completion without waiting for an external event.

#### 3. `pkg/dataplane/userspace/manager_worker_arm_5134.go:14-70` & `pkg/dataplane/userspace/manager_ha.go:601-607` — Un-backed-off 5s plain rebind thrashing on permanent bind failure [MAJOR]
- **Evidence**: Go pending-activation retry issues a plain `rebind` every 5 seconds whenever `desired == true && !m.deferWorkers && anyBinding(state == pending)`. `rebind.rs:42-76` calls `reconcile_status_bindings`, which stops all live workers.
- **Analysis**: If a box experiences a permanent binding failure (e.g. NIC hardware fault, missing parent netdev, invalid queue extent), Go will issue a plain `rebind` every 5 seconds indefinitely. Each `rebind` tears down **all healthy workers** across all interfaces in `reconcile`, attempts respawn, hits S4' failure marking, and fails. This creates an endless loop of worker thread teardown/re-creation, high CPU usage, log flooding, and kernel XSK socket churn on a box that is already fail-closed (`ctrl.Enabled = 0`).
- **Fix**: Implement exponential backoff for the pending-activation retry (e.g. 5s -> 10s -> 20s -> 60s cap) and cap maximum retry attempts before stopping and flagging a persistent failure state.

#### 4. `pkg/daemon/daemon_apply_dataplane.go:165-172` & `393-401` — Race condition between `clearDeferWorkers()` and status loop retry [MINOR]
- **Evidence**: `daemon_apply_dataplane.go:167` clears `m.deferWorkers` before MAC programming and completion dispatch (`NotifyLinkCycle` at line 395).
- **Analysis**: Moving `clearDeferWorkers()` to right before completion dispatch shrinks the window, but if a Go periodic status poll tick runs after `clearDeferWorkers()` and before `NotifyLinkCycle()` completes its control request, the status loop sees `!m.deferWorkers && anyBinding(state == pending)` and may fire a concurrent untagged plain `rebind` while `NotifyLinkCycle` is preparing its tagged `rebind`.
- **Fix**: `clearDeferWorkers()` should be atomic with completion dispatch, or the pending-activation retry must check if a tagged completion dispatch is currently in-flight.

---

### Analysis of Attack Surfaces

1. **r5 Nit Folds & Disposition Table**: Sound in intent, but §1 claims fold B6/B8 cleanly while introducing the structural parameter mismatch in `reconcile_status_bindings` (Finding 1) and the transient MAC stranding (Finding 2).
2. **Tri-State Completeness (Open Q1)**: Checked exhaustively. Every path producing `Registered && !Armed` without an explicit operator verb or global fan-out (S1, S2, S3, S4', S5, `update_fabrics`) sets `activation_state = pending`. No unowned producer exists that leaves `Registered && !Armed && state == none`. Completeness holds.
3. **Pending-Activation Retry Blast Radius (Open Q2)**: Unacceptable in present form. Fixed 5s un-backed-off teardown of healthy workers causes severe resource thrashing (Finding 3).
4. **Completion-After-MAC-Failure (Open Q3)**: Unsafe. Suppressing completion without daemon-side MAC retry debt strands transient MAC failures indefinitely (Finding 2).
5. **Latch-Consume Atomicity (Open Q4)**: Broken by function signature mismatch. `reconcile_status_bindings` cannot evaluate `complete_deferred` without a signature change, creating an atomicity hazard (Finding 1).
6. **Plain Restoration vs #4952 Pins**: Sound. Restoring `guard.snapshot` and `existing_bindings` wholesale preserves the exact pre-apply vector (identities, ifindexes, claims), marks non-operator slots pending via S4', and lets `refresh_bindings` update volatile fields against live workers. This eliminates the live-sysfs race and vector incoherence while preserving #4952's fail-closed reporting invariant.
7. **`update_fabrics` Replan on Set Change (Open Q5)**: No rate concern. Replan executes in-memory vector construction only on `fabrics` set changes; it does not call `reconcile_status_bindings` or tear down workers.
8. **Test Plan Audit (Items 12-19)**: Item 13 must explicitly assert `m.deferWorkers == true` after failed MAC programming; Item 17 should include same-plan generation bump tests.
9. **New Hazards vs Master**: Hazards 1, 2, and 3 identified above are introduced by v7's completion and retry restructuring.

---

DEMAND-REVISION
