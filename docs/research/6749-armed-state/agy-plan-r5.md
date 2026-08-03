### Requested Evidence Gaps
Before presenting the review, the following files outside the inline excerpts would provide fuller verification:
1. `pkg/dataplane/userspace/daemon_apply_dataplane.go`: To inspect the exact error-handling and unwinding logic when RETH MAC programming is cancelled or fails, confirming how `m.deferWorkers` cleanup interacts with `NotifyLinkCycle` under daemon-level aborts.
2. `userspace-dp/src/afxdp/coordinator/reconcile/mod.rs`: To inspect the exact internal sequence of `afxdp.reconcile()` relative to worker teardown and where `ReconcileError::WorkerSpawn` / `WorkerBindIncomplete` are instantiated.
3. `pkg/dataplane/userspace/process_status.go`: To verify whether the return value of `syncDesiredForwardingStateLocked()` is rate-limited before logging at `Warn`.

---

### Adversarial Plan Review (v6)

#### 1. Tri-State Completeness & Unowned Producer Audit (Open Q1)
The v6 tri-state `activation_state ∈ {none, pending, operator}` model closes the ambiguity of v5's single boolean:
- `pending`: Planner-owned. Set on initial creation (S1/S5), deferred plan-changing apply (S3), or post-teardown bring-up failure (S4'). Re-registered via E2. Auto-converged ONLY upon a successful, defer-authorized armed reconcile.
- `operator`: Operator-verb owned. Set by `set_binding_state` / `set_queue_state`. Re-registers into its exact claim via E2. Never auto-converged. Dies only on an explicit global fan-out (C3).
- `none`: Global fan-out owned or normal armed state. Set when a slot reaches `registered && armed` (C1) or via `set_forwarding_state` fan-out on registered slots (C3).

*Attack / Audit Result:* There is no path where a slot lands in `Registered && !Armed && activation_state == none` without an explicit operator disarm (`operator`) or global disarm (`none` with `desired == false`).
- On initial startup, default slots start `registered=false, armed=false, activation_state=none`. The first replan transforms new `ifindex > 0` slots into `registered=true, armed=false, activation_state=pending` (S5).
- If global forwarding is disarmed (`set_forwarding_state(false)`), C3 sets `armed=false, state=none` on registered slots, but `desired` in Go becomes `false`, so Go's Option D drift detector (`manager_ha.go`) does not fire.
- If an arm attempt fails (S4'), all registered non-operator slots are marked `pending`, NOT `none`.
- If an older helper binary sends a status response omitting `activation_state`, Go deserializes `activation_state` as `none`. Go's D predicate (`Registered && !Armed && state == none` when `desired == true`) correctly flags this as drift / version mismatch.

The tri-state provenance model is complete and unowned producers are structurally excluded.

#### 2. Coherent-Vector Invariant & Replan on Failure (Open Q2)
v6 eliminates the v5 plan gate and its live-sysfs authorization race (Codex r4 M9) by establishing **INVARIANT 2**: after every handler, the binding vector MUST equal the stored snapshot's plan.

*Attack / Audit Result:*
- **Post-Teardown Worker Bring-up Failure:** When `reconcile_status_bindings` returns `WorkerSpawn` or `WorkerBindIncomplete`, the handler restores `guard.snapshot = prev_snapshot` (Snapshot A) and replans Snapshot A against the retained post-S4' vector.
  - *Expansion Failure (`[a,b] -> [a,b,c]`):* Replanning Snapshot A against the 3-slot vector drops the B-only identity `c` and restores the 2-slot vector for A with all non-operator slots marked `pending`.
  - *Contraction Failure (`[a,b,c] -> [b,c]`):* Replanning Snapshot A against the 2-slot vector sees `a` missing (`!had_existing`), re-creates `a` via S5 (`registered=true, armed=false, pending`), and yields a 3-slot vector matching Snapshot A.
  - *Same-name / New-ifindex Failure:* Replanning Snapshot A resolves the ifindex from Snapshot A's stored struct, restoring physical coherence.
- **Pre-Teardown Integrity Failure (`#3789`):** Aborts before worker teardown (`snapshot.rs:240,350`). The prior snapshot and its exact binding vector `existing_bindings` are restored without replanning. Because workers were never stopped, the restored vector remains coherent with `prev_snapshot`.
- **Sysfs Race Exclusion:** Because `replan_queues` on the failure path reads candidates directly from `guard.snapshot` (which has been restored to `prev_snapshot`), it never queries live sysfs or netlink during replan. The authorization race is completely closed.

#### 3. Go Arm-Sync Defer Gate & Completion Path (Open Q3 & Q4)
Under v6, `syncDesiredForwardingStateLocked()` in `manager_ha.go:601` skips issuing `set_forwarding_state(true)` while `m.deferWorkers == true`.

*Attack / Audit Result:*
- **Completion via `NotifyLinkCycle` (`process_linkcycle.go:219`):** Upon link cycle completion, Go sends `ControlRequest{Type: "rebind", CompleteDeferred: true}`. In `rebind.rs`, the helper reconciles, and because `complete_deferred == true`, `reconcile_status_bindings` arms all `pending` slots.
- **Completion via `#5134` Debt Retry (`manager_worker_arm_5134.go:48-65`):** If no link cycle occurs (e.g. MAC programming aborted), `retryDeferredWorkerArmLocked()` republishes `apply_snapshot` with `DeferWorkers = false`. In `snapshot.rs`, `guard.snapshot` is updated to a non-deferred snapshot. `reconcile_status_bindings` sees `stored.defer_workers == false` and arms all `pending` slots.
- **Protection Against Stale Arming:** If Go clears `m.deferWorkers` in Go memory without calling `NotifyLinkCycle` or re-publishing `DeferWorkers = false`, any subsequent `set_forwarding_state(true)` sent to the helper will hit the helper's defer gate (`stored.defer_workers == true` without `complete_deferred`). The helper correctly refuses to arm/converge the slots, preserving the defer contract until Go explicitly updates the stored snapshot or signals link completion.

#### 4. Arm Verb Rollback & S4' Locus (Open Q5 & Q6)
- **Arm Rollback & Desired-Loop Retry:** When `set_forwarding_state(true)` fails during reconcile, `forwarding_armed` is restored to `false` (rollback) and `ok=false` is returned. On the next status poll (~1s), `syncDesiredForwardingStateLocked` sees `ForwardingArmed == false != desired (true)` and retries `set_forwarding_state(true)` via Go's existing desired-state loop.
- **S4' Common Locus:** Moving S4' into `reconcile_status_bindings` ensures that ANY post-teardown bring-up failure (full apply, same-plan apply, rebind, binding toggle, queue toggle, forwarding arm) marks all non-operator registered slots `armed=false, state=pending`.
  - On an established box with `forwarding_armed == true`, a failed rebind or toggle marks surviving slots `armed=false, state=pending` and recomputes `enabled = false`. This accurately reflects that workers are dead and avoids master's false-`enabled` reporting.

---

### Numbered Findings

#### Finding 1 (MINOR): Un-ratelimited `Warn` logging during `#6165` protocol gate refusal on rolled-back arm retry
- **File & Line Anchor:** `pkg/dataplane/userspace/manager_ha.go:627-634`
- **Description:** When an arm attempt rolls back on reconcile failure (`forwarding_armed` restored to `false`), Go's `syncDesiredForwardingStateLocked()` will retry on every status poll tick (~1s). If the helper's running snapshot protocol version is stale, `ensureRequiredSnapshotProtocolLocked` returns an error (`manager_ha.go:630`). The poll caller in `process_status.go` will catch this error and log `slog.Warn` on every ~1s tick. While the operation is correctly fail-closed and non-flapping, un-ratelimited per-tick `Warn` logging violates project control-plane logging volume guidelines during extended protocol mismatches.
- **Recommendation:** Wrap the error logging in `process_status.go` for `syncDesiredForwardingStateLocked()` with a rate-limiter (e.g. log on state transition or at most once per 60s).

#### Finding 2 (NIT): Documentation clarification on Go daemon defer-clearing without `NotifyLinkCycle`
- **File & Line Anchor:** `userspace-dp/src/server/README.md` (§9 docs item)
- **Description:** The README documentation of the defer contract should explicitly note that clearing `m.deferWorkers` on the Go manager side is insufficient to activate pending bindings in the helper; either `NotifyLinkCycle` must send `rebind` with `complete_deferred = true` or a new snapshot with `defer_workers = false` must be published via `apply_snapshot`.

---

### Round 5 Final Verdict

PLAN-READY-WITH-NITS
