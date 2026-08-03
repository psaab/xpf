### Adversarial Plan Review: xpf #6749

---

### Findings

#### 1. [MAJOR] Option C State-Machine Flaw: Interfaces Transitioning from `ifindex <= 0` to `ifindex > 0` Remain Disabled Indefinitely
- **File:Line**: `userspace-dp/src/server/helpers/planning.rs:507-522` & Plan Doc §5 (Option C specification)
- **Details**: 
  In `planning.rs:507-512`, `had_existing` is derived as:
  ```rust
  let had_existing = binding.last_change.is_some()
      || binding.registered
      || binding.armed
      || binding.ready
      || binding.bound
      || binding.xsk_registered;
  ```
  Whenever any binding slot is initialized (even if `ifindex <= 0`), line 524 attaches `binding.last_change = Some(Utc::now())`. Consequently, on any subsequent snapshot apply, any carried binding record in `existing` (or `existing_by_identity`) has `binding.last_change.is_some() == true`, so `had_existing` evaluates to `true`.
  
  In Option C's proposed initialization logic (§5):
  ```rust
  if binding.ifindex <= 0 {
      binding.registered = false;
      binding.armed = false;
      binding.ready = false;
  } else if !had_existing {
      binding.registered = true;
      binding.armed = forwarding_armed;
  }
  ```
  If an interface initially possessed `ifindex <= 0` (e.g. uninitialized netdev at boot or missing netdev entry), `binding.registered` and `binding.armed` were explicitly set to `false`. When a subsequent snapshot update assigns a valid `ifindex > 0`, the record is retrieved from `existing_by_identity` with `had_existing == true`. Because `!had_existing` evaluates to `false`, the `else if !had_existing` block **does not execute**. 
  
  As a result, `binding.registered` and `binding.armed` remain `false` forever, leaving any interface that transitions from `ifindex <= 0` to `ifindex > 0` completely un-registered and un-armed.
- **Required Fix**: The re-arm/re-register condition must check whether the binding is currently unregistered/unarmed due to `ifindex <= 0` in addition to `!had_existing`:
  ```rust
  if binding.ifindex <= 0 {
      binding.registered = false;
      binding.armed = false;
      binding.ready = false;
  } else if !had_existing || !binding.registered {
      binding.registered = true;
      binding.armed = forwarding_armed;
  }
  ```

---

#### 2. [MINOR] Volatile Worker State Spills Across Carry Replans in Option C
- **File:Line**: `userspace-dp/src/server/helpers/planning.rs:482-531` & Plan Doc §5 (Option C)
- **Details**:
  When `BindingStatus` is cloned into `existing_by_identity` and carried over to a new plan, volatile worker flags (`ready`, `bound`, `xsk_registered`) are preserved on the carried record before `reconcile_status_bindings` runs. While `coordinator/refresh_bindings.rs` eventually re-derives these fields from live sockets, carrying stale `ready=true` or `bound=true` flags during the brief window between `replan_queues` and coordinator reconcile can report inaccurate state in `guard.status` if snapshot apply encounters an error prior to worker reconcile.
- **Required Fix**: When carrying an existing identity record in `replan_bindings_from_candidates`, reset volatile fields (`binding.ready = false; binding.bound = false; binding.xsk_registered = false;`) so state re-derivation starts clean from actual worker reconcile.

---

#### 3. [NIT] Server Test Assertion Plan Should Include Direct Validation of Go Map Admission Gates
- **File:Line**: `pkg/dataplane/userspace/maps_sync.go:76-99`, `maps_sync.go:438-450`, `userspace-dp/src/server/tests.rs`
- **Details**:
  Plan §9 specifies asserting `status.enabled == true` and all bindings `registered && armed` in `userspace-dp/src/server/tests.rs`. To guard against future regressions in the Go control gate, the test plan should explicitly verify that `probeBindingsReady` evaluates to `true` and that `bindingForwardingLive` permits `userspaceBindingReady` map entry creation when fed the post-expansion status.

---

### Evaluation of Plan Attack Surfaces & Open Questions

1. **Failure Chain Accuracy**: 
   **Verified exact.** 
   - `planning.rs:521`: `!had_existing` sets `registered=true` but leaves `armed=false`.
   - `status.rs:280`: `all(|b| b.registered && b.armed)` returns `false` $\rightarrow$ `status.enabled = false`.
   - `maps_sync.go:391`: `else if status.Enabled` is skipped, leaving `ctrl.Enabled = 0`.
   - `manager_ha.go:603`: `syncDesiredForwardingStateLocked` sees `m.lastStatus.ForwardingArmed == desired` (`true == true`) and returns early without acting.

2. **Soundness of `(interface, queue_id)` Identity Carry**:
   **Sound.** In `planning.rs:374-480`, `seen_linux` guarantees that interface candidate names in `candidates` are unique. `queue_id` spans `0..queue_count`. Thus `(interface, queue_id)` forms a unique tuple for every planned binding across orphan VLAN re-keys and fabric parents.

3. **Rejection of Option B (Go Per-Binding Reconcile)**:
   **Sound rejection.** As established in §5-B, `SetBindingState`/`SetQueueState` (`manager_status.go:132-180`) permit operators to disarm individual slots for diagnostics. A Go-side loop auto-arming `Registered && !Armed` slots cannot distinguish planner default from an operator diagnostic override without wire-protocol provenance flags, and introduces a ~1s poll latency window of transit drop.

4. **Safety & Invariant Preservation**:
   - **#1666 Ready-Gate (`maps_sync.go:76-99`)**: Preserved. `bindingForwardingLive` requires `b.Ready` in addition to `Armed`.
   - **#869 Enabled Gate (`status.rs:267-273`)**: Preserved. `enabled` does not require `ready`.
   - **#5171 Defer Contract (`snapshot.rs:285-355`)**: Preserved. When `defer_workers=true`, `forwarding_armed` is `false`, so new slots initialize `armed=false`.
   - **Required-Protocol Gate (`manager_ha.go:616-630`)**: Preserved. Global arming checks protocol version before setting applied `forwarding_armed`.

5. **Slot-Positional Consumers**:
   `set_binding_state` (`handlers/binding.rs`), `summarize_queues` (`status.rs`), and shim `userspace_bindings` map indexing all remain intact. Option C preserves positional `slot`, `queue_id`, and `worker_id` assignments in layout order.

6. **Answers to Open Questions Q1–Q7**:
   - **Q1 (Applied vs Requested)**: Under `ServerState` lock serialization (`handlers/snapshot.rs`), control requests are strictly ordered. Go disarms before publishing non-supported configs (`manager_ha.go:601`). `guard.status.forwarding_armed` at replan time accurately reflects Go's applied state.
   - **Q2 (Planner as sole drift source)**: Yes. No other non-operator path sets `armed=false` on a registered binding while globally armed.
   - **Q3 (Pinned behavior)**: No pinned tests rely on slot-positional counter inheritance across reshuffles.
   - **Q4 (`last_error` provenance)**: Identity carry of `last_error` is correct; it prevents errors on `ge-0-0-0` from polluting `ge-0-0-1` after a plan reshuffle.
   - **Q5 (VLAN-alias consumer)**: `buildUserspaceIngressBindingAliases` (`maps_sync.go:745`) keys on `(Ifindex, QueueID)`, which layout positioning assigns independently of state provenance.
   - **Q6 (Fail-fast invariant)**: Asserting `all(registered == armed)` in unit/integration tests is good; doing so as a production `debug_assert!` would panic if an operator diagnostic disarm was active.
   - **Q7 (Severity & Release Notes)**: High severity is accurate. A release note / upgrade note is warranted due to the total transit outage blast radius on live interface geometry changes.

7. **Regression Test Behavior on Master**:
   **Red on master today.** Applying Snapshot A, arming, and applying Snapshot B (with an added interface) leaves new slots `armed=false` in `replan_bindings_from_candidates` (`planning.rs:521`), causing `status.enabled` (`status.rs:280`) to evaluate to `false`.

---

### Evidentiary Gaps

No additional file access was required; the provided excerpts completely covered the mechanism chain in both Rust (`userspace-dp`) and Go (`pkg/dataplane/userspace`).

---

DEMAND-REVISION
