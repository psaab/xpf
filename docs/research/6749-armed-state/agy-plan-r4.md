### Round 4 Adversarial Review Summary — xpf Issue #6749 (v5 Plan Model)

The v5 plan model (`docs/research/6749-armed-state/plan.md @ 0c0b9b677`) has been reviewed against the inline source excerpts and plan documentation. 

---

### 1. Disposition Verification of Round-3 Findings

All four round-3 findings raised in AGY Round 3 have been correctly and robustly folded into v5:

* **f1 → Planner never arms (MAJOR):** **CLOSED.** Section 5-C S5 eliminates arm-at-replan. New and E2 re-registered slots are initialized as `registered=true, armed=false, activation_pending=true` unconditionally. Slots arm strictly via the post-`Ok` convergence locus in `reconcile_status_bindings`, explicit operator verbs (C2), or post-`Ok` global arm fan-outs (C3).
* **f2 → Was-armed gate on S2 & mark rules (MAJOR):** **CLOSED.** Section 5-C S2 enforces that `ifindex <= 0` force-clears mark `pending=true` *only* if the slot was `armed` (or already `pending`) prior to the clear. Operator-disarmed slots (`registered && !armed && !pending`) flap to `registered=false` without a mark and recover as `registered=false, pending=false` (§10 documented degradation), preventing flap-induced re-arming.
* **f3 → Test 7(c) split (MINOR):** **CLOSED.** Section 9 item 7 explicitly splits (c-i) armed slot flap (re-registers and converges) from (c-ii) operator-disarmed slot flap (force-cleared without a mark, recovers as `registered=false, pending=false`).
* **f4 → Prominent release & upgrade note (NIT):** **CLOSED.** Section 9 (Docs) and §11 specify prominent release notes covering (1) the explicit `systemctl restart xpf-userspace-dp` requirement on upgrade, and (2) the fail-closed posture change during deferred plan-changing applies.

---

### 2. Attack Surface Analysis

1. **Round 3 Findings Closure Audit (f1/f2/f3/f4):** Confirmed closed as detailed above. No claimed-but-wrong dispositions were found.
2. **Marker Lifecycle Completeness (Open Q1):** No un-marked path to `Registered && !Armed` exists without an explicit operator verb. All creation branches (S1, S5, E2) initialize `activation_pending=true`. All teardown/failure branches (S2, S3, S4') preserve or set `activation_pending=true` on non-operator slots. Disarmed reconciles leave `pending=true` intact, which converges cleanly when `set_forwarding_state(true)` or `rebind` runs next.
3. **Plan Gate Sufficiency (Open Q2):** The convergence check `in_current_plan` evaluates `replan_queues(stored_snapshot, workers, bindings)` against the stored snapshot. If Snapshot B fails bring-up post-teardown and Snapshot A is restored in memory (the #4952 path), `stored_snapshot` is Snapshot A. B-only pending identities in the retained vector fail `in_current_plan` and stay `armed=false, pending=true`. Slots shared with A are validated at the `Ok` boundary by `bound == planned` ([bringup.rs:188](file:///userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs#L188)), ensuring no slot converges without fully bound workers.
4. **Defer Gate & Mid-Window Rebind Flap (Open Q3):** A link-flap `rebind` mid-defer-window executes `afxdp.reconcile`. If `afxdp.reconcile` returns `Ok`, workers are live and bound to the kernel netdevs; arming them at the rebind-authorized locus is correct and operational. If subsequent RETH MAC cycles happen later, the kernel link-down/up destroys the XSK pool, triggering `NotifyLinkCycle` -> `rebind` again, which re-reconciles cleanly. The sequence is self-consistent.
5. **C3 Reorder (`set_forwarding_state`):** Reordering the arm fan-out after `reconcile_status_bindings` returns `Ok` ([forwarding.rs:40-52](file:///userspace-dp/src/server/handlers/forwarding.rs#L40-L52)) prevents stranding armed-mark-free slots on bring-up failures. `should_run_afxdp` evaluates `forwarding_armed == true` during the reconcile, driving worker bring-up; convergence runs post-`Ok`, and C3 fans out `armed=true` to registered slots.
6. **S4' + #4952 Retained-Vector Semantics:** On post-teardown bring-up failure (`WorkerSpawn`/`WorkerBindIncomplete`), S4' marks all non-operator registered slots `armed=false, pending=true`. `refresh_status` recomputes `enabled=false`, holding transit fail-closed while `guard.snapshot` rolls back to last-good Snapshot A. The state is truthful, fail-closed, and self-heals on subsequent retries.
7. **Test Plan Items 12–17:** The expanded test plan in §9 covers immediate post-failure assertions, all three completion shapes, operator-override retention across failures, and mid-window registration toggle blocks. An unsafe implementation cannot pass this matrix.
8. **New Hazards:** None identified.

---

### 3. Detailed Findings

#### Finding 1 (NIT): `forwarding.rs` in-memory `forwarding_armed` rollback on reconcile failure
* **Location:** [userspace-dp/src/server/handlers/forwarding.rs:36-48](file:///userspace-dp/src/server/handlers/forwarding.rs#L36-L48)
* **Description:** In `set_forwarding_state`, `guard.status.forwarding_armed` is set to `forwarding_req.armed` (e.g. `true`) prior to calling `reconcile_status_bindings`. If `reconcile_status_bindings` returns `Err`, the handler sets `response.ok = false` and returns early. While `refresh_status` correctly sets `status.enabled = false` (keeping the dataplane fail-closed) and C3 skips the per-binding arm fan-out, `guard.status.forwarding_armed` remains `true` in memory despite the failed arm operation.
* **Recommendation:** Save `prev_forwarding_armed = guard.status.forwarding_armed` and restore it on `reconcile_status_bindings` `Err` inside `forwarding.rs`, mirroring the snapshot rollback pattern in [snapshot.rs:356-396](file:///userspace-dp/src/server/handlers/snapshot.rs#L356-L396).

#### Finding 2 (NIT): `rebind.rs` log trace enhancement for `activation_pending`
* **Location:** [userspace-dp/src/server/handlers/rebind.rs:70-76](file:///userspace-dp/src/server/handlers/rebind.rs#L70-L76)
* **Description:** The trace log at line 72 prints `forwarding_armed` and `bindings.len()`. Including the count of `activation_pending` slots before and after `reconcile_status_bindings` will simplify field diagnosis of deferred link-cycle completions.
* **Recommendation:** Add `pending_count` to the `rebind` completion `eprintln!` statement.

---

### 4. Evidence Sufficiency Declaration

The inline source excerpts provided from `status.rs`, `planning.rs`, `snapshot.rs`, `rebind.rs`, `forwarding.rs`, `binding.rs`, `bringup.rs`, `process_linkcycle.go`, `manager_worker_arm_5134.go`, and `maps_sync.go` provided complete visibility into the status flags, plan key transitions, reconcile error handling, and Go control loops. No additional file reads or command executions were needed.

---

PLAN-READY-WITH-NITS
