I am going to check the available permissions first to determine if I need to request access to the worktree path.
I will request read-only file access to the specific worktree directory where the plan is located, allowing me to view and analyze it efficiently.
I will now read the v7 plan file to understand the context, the A.3 and A.5 sections, and the questions in section 11.
I will read the relevant parts of the codebase mentioned in the plan, beginning with the tunnel manager implementation in `pkg/routing/tunnel.go`.
I will read `pkg/daemon/daemon_apply.go` to see the VRF binding sequence (step 0a) and how it coordinates with the tunnel manager.
I will check the files inside `docs/research/1884-tunnel-flap/` to see if there are earlier plan versions, research notes, or findings files that can give more context on r5 or r6 findings.
I will view the `agy-plan-r5.md` file to see my previous findings that were folded into the v6 plan.
I will view the implementation of `BindInterfaceToVRF` in `pkg/routing/vrf.go` to understand how it handles interface mastering and if there are constraints when an interface is already slaved to a VRF.
I will look up how the compiler stage reconciles the interface MTU in `pkg/dataplane/compiler_iface.go` to verify if it resets the MTU to a default value when the MTU config is removed.
I will view the code around line 351 in `pkg/dataplane/compiler_iface.go` to see the conditions under which the compiler sets the MTU.
I will view the code around line 440 to 465 in `pkg/dataplane/compiler_iface.go` to see the second MTU setting condition.
I will view the code around line 540 to 565 in `pkg/dataplane/compiler_iface.go` to inspect the third MTU setting condition.
### Verdict: PLAN-READY

---

### Confirmation of r5 Findings Closure

1. **Unit > 0 Normalization Divergence (agy-plan-r5: L45-75)**: Genuinely closed. Extracting the **shared normalization helper** between step `0a` and `collectAppliedTunnels` ensures that the list-veto logic and the bind logic use identical string matching rules and cannot diverge. The pre-existing naming mismatch for `unit > 0` tunnels (where `0a` attempts to bind `.1` but the kernel device is named `u1`) is correctly isolated as an out-of-scope follow-up issue in section 10, and fixing it in the shared helper will automatically update the veto scan as well.
2. **Unzoned Owned Tunnel MTU Changes (agy-plan-r5: L82-90)**: Genuinely closed in the v7 text (lines 286–293). Reconciling the MTU on *every* reuse when `tc.MTU > 0` (rather than only on `adopting == true`) ensures that unzoned tunnel MTU edits are successfully written to the kernel dev, even though the zoned-only compiler stage ignores them.

---

### Question 1: Guarded Transfer Completeness

The guarded transfer implementation is **complete and correct**. There is no sequence of configuration changes or transient failures where a retained OLD claim combined with a later-succeeding step `0a` bind to a NEW list RI produces an incorrect unbind or a stuck claim. 

#### 1. Synchronous Execution Guarantee
Step `0a` (`BindInterfaceToVRF`) and step 1 (`ApplyTunnels` / `Apply`) execute sequentially in a single synchronous execution path within `applyConfig`, which runs under the global configuration lock (`applySem`). This guarantees there are no race conditions or TOCTOU gaps between step `0a` attempting the bind and `ApplyTunnels` checking the current kernel `MasterIndex`.

#### 2. Claim State Evolution Under Failures & Recovery
If we transition a tunnel from stanza-bound `A` to list-bound `B`:
* **State 1 (Commit 1)**: Stanza `A` $\rightarrow$ `appliedRI` is `A`. Kernel master is `vrf-A`.
* **State 2 (Commit 2, 0a bind to B fails)**: Stanza is empty, `RIListMember` is `B`.
  * Step `0a` fails to bind the tunnel to `vrf-B`. Kernel master remains `vrf-A`.
  * `ApplyTunnels` runs. The veto suppresses unbinding (since `tc.RIListMember != ""`).
  * The transfer guard compares `MasterIndex` (index of `vrf-A`) against the index of `vrf-B`. They mismatch, so the old claim `A` is **retained**.
  * The interface remains bound to `vrf-A` in the kernel, and the claim correctly reflects `A`.
* **State 3 (Commit 3, 0a bind to B succeeds)**: Config is still empty stanza, list `B`.
  * Step `0a` succeeds in binding the tunnel to `vrf-B`. Kernel master is now `vrf-B`.
  * `ApplyTunnels` runs. The veto still suppresses unbind.
  * The transfer guard compares `MasterIndex` (index of `vrf-B`) against the index of `vrf-B`. They match, and the claim is updated to `B`.
* **State 4 (Commit 4, list membership removed)**: Stanza is empty, `RIListMember` is empty.
  * Step `0a` does nothing.
  * `ApplyTunnels` runs. Since both are empty and the claim is `B`, the unbind is triggered.
  * The identity check resolves `vrf-B`. Its index matches `MasterIndex`, so it calls `LinkSetNoMaster` to unbind the tunnel and clears the claim.

#### 3. List-Removal Before Recovery
If the user removes the list membership `B` (Commit 3) *before* the bind to `B` ever succeeds:
* Config: Stanza empty, `RIListMember` empty. Claim is `A`. Kernel master is still `vrf-A`.
* `ApplyTunnels` runs: Since both are empty, it triggers the unbind.
* The identity check resolves `vrf-A`. Its index matches `MasterIndex` (still `vrf-A`), so it calls `LinkSetNoMaster` to unbind the tunnel from `vrf-A` and clears the claim. The link is successfully unbound.

---

### Question 2: Other Defects & Re-opened Closures

No other defects are introduced, and no earlier closures are re-opened.

#### 1. VRF Rename and Deletion Safety
Using `LinkByName(appliedRI[name]).Index == link.Attrs().MasterIndex` is a highly resilient test.
* If a VRF is renamed or deleted, `vrfManager.Reconcile` deletes the old VRF device.
* Upon deletion of a VRF master device, the Linux kernel automatically unslaves all member interfaces, resetting their `MasterIndex` to `0`.
* Thus, the next time the tunnel manager runs, `MasterIndex` will be `0` (or the VRF lookup for the old name will return a not-found error), which fails the identity comparison, preventing any incorrect unbind operations and safely clearing the stale claim.

#### 2. MTU Reconcile Alignment with Project Invariants
For owned reuse when `tc.MTU == 0`, the tunnel manager does not modify the link's MTU. This matches the project-wide behavior of the compiler stage (in [pkg/dataplane/compiler_iface.go:348,450,550](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/compiler_iface.go#L348-L350)), which only applies configuration-driven MTUs when they are explicitly `> 0`.

#### 3. Safe Bounded Stanza-Bind Failures (Minor Operational Detail)
If a stanza-nonempty bind fails (e.g., if the user configures stanza `B` but `vrf-B` does not exist), the claim `appliedRI[name]` is set to `B` regardless of the failure. If the user then removes the stanza altogether in the next commit, the manager will observe a mismatch between the claim `B` and the actual master (which remained `0` or `vrf-A`), clear the claim, and bypass calling `LinkSetNoMaster`. While the tunnel will remain in its degraded kernel state, this is the safest course of action (it avoids blindly unbinding a master device the manager did not set), and matches the expectation for recovery of a misconfigured state.
