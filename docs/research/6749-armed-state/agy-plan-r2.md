### Explicit Note on Missing / Desired Evidence

Before presenting findings, per instructions, here is where additional inline evidence would have been desirable to verify all boundary conditions:
1. **Full source of `replan_queues` invocation context in `snapshot.rs` (around line 345):** To confirm how `guard.status.forwarding_armed` and `snapshot.defer_workers` are passed into the planner call.
2. **Complete error-handling paths in `reconcile_status_bindings` (status.rs:373-415):** To inspect whether any error branch clears or modifies `bindings` in place when `afxdp.reconcile()` returns an `Err`.
3. **Go daemon snapshot generation & dispatch (`daemon_apply_dataplane.go` & `manager_compile.go`):** To trace exact triggers where a defer-clearing commit (`DeferWorkers=false`) coincides with plan-key mutations.

---

### Round 2 Adversarial Findings

#### Finding 1: [BLOCKER] R2 Defer-Completion Fan-Out is Placed Exclusively on `same_plan` Leg; Plan-Changing Defer Completion Strands Slots Indefinitely
* **Location:** [snapshot.rs:159-245](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/handlers/snapshot.rs#L159-L245), [snapshot.rs:285-360](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/handlers/snapshot.rs#L285-L360), [planning.rs:482-531](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/helpers/planning.rs#L482-L531)
* **Impact:** High — Dataplane remains disabled (`enabled=false`) indefinitely after defer-completion commits that alter the plan key.
* **Analysis:**
  Trace the execution path for a deferred plan expansion followed by completion:
  1. **Snapshot 1 (Deferred Apply):** `defer_workers = true`. Plan expansion creates new slots. Per R1, `armed = forwarding_armed && !defer_workers` evaluates to `false`. These slots land in `guard.status.bindings` with `armed = false`. Reconcile is skipped.
  2. **Snapshot 2 (Defer Completion + Plan Mutation):** The defer-clearing commit (`defer_workers = false`) arrives. If Snapshot 2 contains any modification to plan key inputs (e.g. adding another candidate interface, CoS queue change, or candidate set reshuffle), `same_plan` ([snapshot.rs:163-174](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/handlers/snapshot.rs#L163-L174)) evaluates to `false`.
  3. Execution branches to the `else` (full-apply) leg ([snapshot.rs:285-360](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/handlers/snapshot.rs#L285-L360)). `replan_queues` is called with `existing_bindings` (which contains the Snapshot 1 slots with `armed = false`).
  4. Under R3, identity carry matches existing slots by `(interface, queue_id)` and carries `armed = false` from `existing_bindings`. They are *not* treated as new/never-registered slots.
  5. `reconcile_status_bindings(guard)` runs and succeeds, binding the XSKs.
  6. **Failure:** R2's `set_bindings_forwarding_armed(..., true)` fan-out was placed *only* inside the `if same_plan` block ([snapshot.rs:175-238](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/handlers/snapshot.rs#L175-L238)). The `else` leg has no defer-completion activation check! Consequently, the carried slots retain `armed = false` after reconcile succeeds. `status.enabled` remains `false` indefinitely, stranding the dataplane.

---

#### Finding 2: [MAJOR] R1 Pre-Arming in `replan_queues` Causes False `enabled = true` Reporting on Post-Teardown Reconcile Failures
* **Location:** [snapshot.rs:355-360](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/handlers/snapshot.rs#L355-L360), [status.rs:274-281](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/helpers/status.rs#L274-L281), [planning.rs:518-522](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/helpers/planning.rs#L518-L522)
* **Impact:** Medium-High — Dataplane fail-closed protection bypassed on worker bring-up failure; traffic steered to unbound/dead XSKs.
* **Analysis:**
  R1 initializes new slots in `replan_queues` with `armed = forwarding_armed && !defer_workers` *before* `reconcile_status_bindings` is invoked.
  On a non-deferred full apply (`same_plan == false`):
  1. `replan_queues` assigns `guard.status.bindings = replanned`, where new slots have `armed = true`.
  2. `reconcile_status_bindings(guard)` is called and returns an `Err(WorkerSpawn)` or `Err(WorkerBindIncomplete)`.
  3. The error handler ([snapshot.rs:355-360](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/handlers/snapshot.rs#L355-L360)) sets `response.ok = false`, but does *not* unwind or disarm `guard.status.bindings`. It calls `refresh_status(guard)`.
  4. `refresh_status` recomputes `state.status.enabled` ([status.rs:274-281](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/helpers/status.rs#L274-L281)). Since all registered slots were pre-armed by R1, `enabled` evaluates to `true` despite the bring-up failure!
  5. Go's status poll receives `status.Enabled == true` and sets `ctrl.Enabled = 1` ([maps_sync.go:391-460](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/maps_sync.go#L391-L460)), opening the shim to steer traffic into dead/unbound workers.
  *Correction required:* Arming of new slots must be conditional on reconcile completion, or disarmed explicitly on reconcile error.

---

#### Finding 3: [MAJOR] E2 `never_registered` Widening Erases Operator Unregister Overrides Across Temporary Interface Down/Flap Transitions
* **Location:** [planning.rs:510-525](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/helpers/planning.rs#L510-L525), Plan doc §5-C R3
* **Impact:** Medium — Operator unregister state silently lost when an interface experiences a transient flap (`ifindex <= 0 → >0`).
* **Analysis:**
  v3's E2 widening defines `never_registered = !binding.registered && binding.ifindex <= 0` from the carried record.
  1. Suppose an operator explicitly unregisters a slot (`registered = false`) while `ifindex > 0`.
  2. The underlying interface flaps or goes down (`ifindex <= 0`). `replan_queues` sets `binding.ifindex = 0` and `binding.registered = false`.
  3. On the subsequent replan when the interface comes back up (`ifindex > 0`), the carried record has `binding.registered == false` AND `binding.ifindex <= 0`.
  4. `never_registered` evaluates to `true`.
  5. `replan_queues` treats the slot as a new slot and re-initializes `registered = true`, silently destroying the operator's explicit unregister override.

---

#### Finding 4: [MINOR] Test Plan Items 12–14 Will Green Broken Implementations
* **Location:** Plan doc §9 (Test Plan items 12–14)
* **Impact:** Low-Medium — Test suite fails to catch Finding 1 and Finding 2.
* **Analysis:**
  * Test item 13 tests defer completion exclusively via a `same_plan` re-apply (`defer_workers=false`). It does *not* include a test case where the defer completion commit also alters the plan key (`same_plan == false`), allowing Finding 1 to pass silently.
  * None of the test items (12–14) simulate a `reconcile_status_bindings` failure (`WorkerSpawn`/`WorkerBindIncomplete`) to assert that `status.enabled` stays `false`, leaving Finding 2 uncovered.

---

#### Finding 5: [NIT] Destructive Overwriting of Diagnostic Operator Disarms During Defer-Completion Fan-Out
* **Location:** Plan doc §5-C R2, §11 (Open Question 1)
* **Impact:** Low — Diagnostic operator disarms issued before/during defer window are overwritten upon defer completion.
* **Analysis:**
  R2 executes `set_bindings_forwarding_armed(status, true)` unconditionally across all bindings when defer-completion succeeds. If an operator disarmed slot X to isolate a broken queue prior to or during a deferred apply, any background defer-completion publish will clear the operator disarm and re-arm slot X.

---

DEMAND-REVISION
