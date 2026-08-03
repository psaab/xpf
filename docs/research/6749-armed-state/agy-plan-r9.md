### Additional Evidence Desired

To evaluate the full execution flow without relying on plan assertions alone, seeing the complete verbatim implementations of the following source files would have been beneficial:
1. `pkg/daemon/daemon_reth.go` (`programRethMAC` internal state updates and error handling)
2. `pkg/daemon/daemon_apply_dataplane.go` (`reapplyAfterDeferredMAC` and `setDataplaneDeferWorkers` implementation)
3. `pkg/dataplane/userspace/manager_ha.go` (`SyncFabricState` and full status loop code)

---

### Round 9 Adversarial Findings

#### 1. [BLOCKER] Two-phase precheck (`mac != desired || !linkUp`) disables the entire dataplane indefinitely when any member link is down
- **Location**: [`docs/research/6749-armed-state/plan.md:320-335`](file:///home/ps/.gemini/antigravity-cli/scratch/docs/research/6749-armed-state/plan.md#L320-L335), [`pkg/daemon/daemon_apply_dataplane.go:45-70`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/daemon/daemon_apply_dataplane.go#L45-L70)
- **Description**:
  In v8.3 (§5-C, MAC debt contract), the `rethMACPending` precheck is defined as `mac != desired || !linkUp` per desired member. If any RETH member interface is administratively down, un-plugged, or has a link carrier down (`!linkUp`), `rethMACPending` evaluates to `true` on EVERY config commit, setting `d.setDataplaneDeferWorkers(true)`. Because the physical link remains down, `!hasActiveMACDebt` NEVER settles, so `m.deferWorkers` stays `true` indefinitely.
  Consequently:
  1. `syncDesiredForwardingStateLocked` ([`manager_ha.go:601`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/manager_ha.go#L601)) hits `if desired && m.deferWorkers { return nil }` and permanently refuses to arm forwarding on the helper.
  2. The generic pending-activation retry requires `!m.deferWorkers` and is permanently suppressed.
  3. All slots remain `armed=false, pending`, forcing `enabled=false` on the helper ([`status.rs:274-281`](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/helpers/status.rs#L274-L281)).
  Thus, a single disconnected cable or standby member link down shuts down packet forwarding across the ENTIRE dataplane for ALL healthy interfaces — directly reproducing issue #6749's outage mode.
- **Remediation**:
  `rethMACPending` (which decides whether to set `deferWorkers = true` to avoid mlx5 zero-copy `EBUSY` during MAC programming) must ONLY check `mac != desired`. Link carrier status (`!linkUp`) must NOT trigger `deferWorkers = true` when `mac == desired`. Link-up validation belongs inside the MAC debt completion state machine, not in the epoch-opening precheck.

---

#### 2. [BLOCKER] Deadlock between synchronous `ApplyDataPlane` / `NotifyLinkCycle` and asynchronous `hasActiveMACDebt`
- **Location**: [`docs/research/6749-armed-state/plan.md:320-350`](file:///home/ps/.gemini/antigravity-cli/scratch/docs/research/6749-armed-state/plan.md#L320-L350), [`pkg/daemon/daemon_apply_dataplane.go:390-401`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/daemon/daemon_apply_dataplane.go#L390-L401), [`pkg/dataplane/userspace/process_linkcycle.go:215-235`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/process_linkcycle.go#L215-L235)
- **Description**:
  v8.3 specifies that `complete_deferred = m.deferWorkers && !m.hasActiveMACDebt`, where `hasActiveMACDebt` is initialized to `true` (`phase-validation-pending`) at epoch opening. v8.3 also mandates that every MAC debt attempt acquires the daemon's `applySem`.
  During a config apply, `ApplyDataPlane` holds `applySem`, executes `programRethMAC`, and invokes `d.dp.Link().NotifyLinkCycle()` ([`daemon_apply_dataplane.go:392`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/daemon/daemon_apply_dataplane.go#L392)).
  When `NotifyLinkCycle` evaluates `CompleteDeferred: m.deferWorkers && !m.hasActiveMACDebt`, `m.hasActiveMACDebt` is STILL `true` because the background MAC debt task could not acquire `applySem` while `ApplyDataPlane` was executing.
  As a result, `CompleteDeferred` evaluates to `false`. `NotifyLinkCycle` sends `ControlRequest{Type: "rebind", CompleteDeferred: false}`. The helper receives `complete_deferred: false` and DOES NOT consume its stored `defer_workers` latch or arm slots ([`status.rs:373`](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/helpers/status.rs#L373)).
  Once `ApplyDataPlane` finishes and releases `applySem`, the background MAC debt task validates netlink and clears `hasActiveMACDebt = false`, BUT the MAC debt task does NOT invoke `NotifyLinkCycle` or send a tagged rebind RPC. The helper remains latched with `defer_workers = true` and `armed = false, pending` forever.
- **Remediation**:
  When synchronous `programRethMAC` in `ApplyDataPlane` succeeds, `hasActiveMACDebt` must be cleared synchronously before `NotifyLinkCycle()` is invoked, OR the MAC debt settlement handler must explicitly issue the tagged completion rebind (`NotifyLinkCycle` / `rebind` with `CompleteDeferred: true`) upon transitioning `hasActiveMACDebt` to `false`.

---

#### 3. [MAJOR] `SyncFabricState` pre-disable clears `neighborsPrewarmed` on guard-hit / rejected fabric RPCs
- **Location**: [`docs/research/6749-armed-state/plan.md:250-280`](file:///home/ps/.gemini/antigravity-cli/scratch/docs/research/6749-armed-state/plan.md#L250-L280), [`pkg/dataplane/userspace/process_linkcycle.go:195-205`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/process_linkcycle.go#L195-L205), [`pkg/dataplane/userspace/manager_ha.go:150-175`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/manager_ha.go#L150-L175)
- **Description**:
  v8.3 specifies that on any `update_fabrics` call where requested projection != cached accepted projection, Go pre-disables `ctrl` (`ctrl.Enabled = 0`) BEFORE sending the RPC.
  If a transient sysfs queue count read fails (`rx_queues == 0`), the helper guard HITS and defers the update, returning the prior accepted snapshot and prior bindings untouched. Go receives the clean response and adopts the helper's returned prior projection.
  However, Go's pre-disable cleared `m.neighborsPrewarmed = false` ([`process_linkcycle.go:198`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/process_linkcycle.go#L198)). Because `neighborsPrewarmed` was reset, `probeBindingsReady` in `maps_sync.go` blocks `ctrl.Enabled` until neighbor prewarming re-completes (~1-2s delay), creating an unnecessary transit outage on a rejected request where the helper's bindings and forwarding state never changed.
- **Remediation**:
  Go's pre-disable on `update_fabrics` projection change must NOT clear `neighborsPrewarmed` if the helper returns a guard-hit / rejected response that retains the prior accepted bindings. `neighborsPrewarmed` should only be reset if the helper actually accepted a projection change that marked bindings pending.

---

#### 4. [MINOR] Missing retry counter reset on explicit operator arm
- **Location**: [`docs/research/6749-armed-state/plan.md:355-385`](file:///home/ps/.gemini/antigravity-cli/scratch/docs/research/6749-armed-state/plan.md#L355-L385), [`pkg/dataplane/userspace/manager_ha.go:600-615`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/manager_ha.go#L600-L615)
- **Description**:
  v8.3 specifies that an explicit operator global arm clears the helper stored latch and manager flag. However, it does not explicitly specify resetting `m.pendingRetryAttempts` and `m.pendingRetryNextAt`. If an operator arms the system after a backoff has reached the 60s floor, a subsequent pending state introduced later will start retrying at the 60s floor rather than resetting to the initial 5s backoff.
- **Remediation**:
  Explicitly specify that any global or per-binding operator arm command resets `m.pendingRetryAttempts = 0` and `m.pendingRetryNextAt = zeroTime`.

---

#### 5. [NIT] Clarify `activation_state` display scope in `show` CLI command output
- **Location**: [`docs/research/6749-armed-state/plan.md:415-425`](file:///home/ps/.gemini/antigravity-cli/scratch/docs/research/6749-armed-state/plan.md#L415-L425)
- **Description**:
  v8.3 notes that `activation-state` may surface in verbose binding output as an additive display field. To ensure backward compatibility with CLI parsing scripts matching standard `show` text output, the plan should explicitly pin that non-verbose CLI output layout is unchanged and `activation_state` is exposed exclusively in JSON and verbose modes.

---

DEMAND-REVISION
