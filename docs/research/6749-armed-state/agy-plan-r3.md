Here is the adversarial PLAN review (Round 3) for xpf issue #6749 (v4 plan doc).

---

### Evidence Wishlist (Where More Code Evidence Was Desired)
While the provided inline excerpts and plan doc are comprehensive, full evaluation of edge cases would have benefited from inspecting:
1. `userspace-dp/src/server/helpers/planning.rs` in full (specifically lines 1–481 covering candidate sorting, layout shape calculation, and queue extent assignment).
2. `pkg/dataplane/userspace/manager_ha.go` (specifically `syncDesiredForwardingStateLocked` around lines 580–640 to inspect exact HA lock holding and status-poll interaction with Option D).
3. The C/BPF dataplane shim source (`userspace_dp_kern.c` / BPF maps definition) to verify the exact precedence order between `userspace_ctrl.Enabled` and per-row `userspace_bindings` admission checks.

---

### Hostile Findings & Attack Surface Analysis

#### Finding 1: MAJOR — S5 premature arming before reconcile creates transient invalid state and forces fragile S4 revert logic
- **File:Line Evidence:** Plan Doc §5-C (S4/S5 definitions); [`userspace-dp/src/server/handlers/snapshot.rs:345-360`](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/handlers/snapshot.rs#L345-L360)
- **Analysis:** Under rule **S5**, non-deferred new slots initialize at `replan_queues` time with `armed = forwarding_armed` (`true`) and `activation_pending = false`. This sets `armed = true` on un-bound slots inside `guard.status.bindings` *before* `reconcile_status_bindings` executes. Because `armed` is prematurely set to `true`, a post-teardown reconcile failure (`WorkerSpawn` / `WorkerBindIncomplete`) forces the plan to introduce **S4** ("revert initialized slots to `armed=false, activation_pending=true`"). S4 then creates an asymmetric state where newly added slots revert to `armed=false, pending=true` while carried slots remain `armed=true`.
- **Fix:** S5 must initialize all new/E2 slots requiring activation as `registered = true, armed = false, activation_pending = true` (even when `forwarding_armed == true`). The *only* place that flips `activation_pending -> armed=true` must be the single convergence locus inside `reconcile_status_bindings` after `afxdp.reconcile` returns `Ok`. This eliminates premature arming before worker creation, renders S4's complex error-path revert redundant (since slots are already `armed=false, pending=true` if reconcile fails), and guarantees worker binding precedes `armed=true`.

#### Finding 2: MAJOR — S2 force-clear marks `activation_pending=true` on operator-disarmed slots during interface flaps, destroying operator intent
- **File:Line Evidence:** Plan Doc §5-C (S2 & E2 rules); [`userspace-dp/src/server/helpers/planning.rs:516-519`](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/helpers/planning.rs#L516-L519)
- **Analysis:** Rule **S2** states that whenever a `registered=true` slot transitions to `ifindex <= 0` during replan, it sets `activation_pending = true`. If an operator deliberately disarms a slot using `set_binding_state(slot, registered=true, armed=false)` (which sets `activation_pending = false` per **C2**), and that slot's underlying interface subsequently flaps (`ifindex <= 0` then `ifindex > 0`), S2 sees `registered=true -> false` and sets `activation_pending = true`. When `ifindex` recovers `> 0`, rule **E2** and the convergence locus auto-arm the slot. This violates Invariant 8 (*"The marker NEVER auto-converges an operator-owned state"*).
- **Fix:** S2 must only set `activation_pending = true` if the slot was previously armed (`registered=true && armed=true`) or already pending (`activation_pending=true`). An operator-disarmed slot (`registered=true && !armed && !activation_pending`) must clear `registered=false` *without* setting `activation_pending=true`.

#### Finding 3: MINOR — Test 7(c) in §9 validates the buggy S2 operator-disarm flap behavior
- **File:Line Evidence:** Plan Doc §9 (Test plan item 7c)
- **Analysis:** Test 7(c) specifies: *"registered slot flaps (S2 marks) -> recovers -> re-registered + converged"*. As written, this test enforces that *any* registered slot flapping `ifindex <= 0 -> > 0` gets marked and auto-armed upon recovery, without distinguishing between an armed registered slot and an operator-disarmed registered slot. Test 7(c) would cause a green suite on an implementation that overwrites operator diagnostic disarms across link flaps.
- **Fix:** Split Test 7(c) into two cases: (i) an armed slot flaps and successfully auto-converges on recovery, and (ii) an operator-disarmed slot (`registered=true, armed=false, pending=false`) flaps and remains `armed=false, pending=false` upon recovery.

#### Finding 4: NIT — S3 global pending gate causes total dataplane disable during deferred plan-changing applies
- **File:Line Evidence:** Plan Doc §5-C (S3 rule); [`pkg/dataplane/userspace/maps_sync.go:391-404`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/maps_sync.go#L391-L404)
- **Analysis:** S3 sets *all* registered slots to `armed=false, activation_pending=true` during a deferred plan-changing apply. This causes `status.Enabled` to evaluate to `false`, driving `userspace_ctrl.Enabled = 0` in Go. While this posture tightening is necessary to prevent mis-steering on shifted identities during deferred contractions or reshuffles, it means a RETH MAC commit will drop transit across *all* interfaces until link-cycle completion (`rebind`). This is architecturally sound for fail-closed safety, but should be called out prominently in the operational release notes.

---

DEMAND-REVISION
