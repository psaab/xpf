verdict — PLAN-NEEDS-REVISION

### (Q1) Ratify or Refute: VRF Identity Test & Lapse Rule

We **refute** the correctness of the index-equality identity test and the lapse rule in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md#L341-L348) due to the following findings:

1. **Lookup Name Prefix Mismatch (Bug in VRF Lookup)**
   - **Finding:** The plan states: *“resolve `t.ops.LinkByName(appliedRI[name])` and require its `Index` == `link.Attrs().MasterIndex`.”*
   - **Defect:** `appliedRI[name]` stores the logical routing instance name (e.g. `"red"`), but the Linux VRF interface name created by the daemon is prefixed with `"vrf-"` (e.g. `"vrf-red"`) in [BindInterfaceToVRF](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L127). Looking up the bare routing instance name via `LinkByName` will return a "link not found" error, meaning the lookup fails.
   - **Consequence:** The unbind logic will always abort on lookup failure, meaning the tunnel will never be unbound when transitioned back to the default VRF.
   - **Remedy:** The lookup must target `"vrf-" + appliedRI[name]`.

2. **Same-VRF List-Bind Transition Flap**
   - **Finding:** If a tunnel moves from stanza-bind `red` to list-bind `red` (same VRF):
     1. Step 0a in [daemon_apply.go](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L218-L238) binds the tunnel to `"vrf-red"`.
     2. `ApplyTunnels` runs. `appliedRI["gr-0-0-0"]` is `"red"`, and `tc.RoutingInstance` is `""`.
     3. The index-equality test matches because step 0a just bound the tunnel to `"vrf-red"`.
     4. `LinkSetNoMaster` is called, unbinding the tunnel from `"vrf-red"`.
   - **Consequence:** The tunnel is incorrectly unbound, leaving it in the default VRF and violating the list-bind user configuration.
   - **Remedy/Alternative:** Re-order [daemon_apply.go](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go) to run `ApplyTunnels` (which unbinds/reconciles first) *before* step 0a (which applies list-binds). This also fixes the pre-existing bug where newly created list-bound tunnels are not bound on the first apply.

3. **VRF Rename Edges & Ifindex Reuse**
   - **Analysis:** Correct. In `reconcileVRFs`, rename/table mismatch results in deletion and recreation of the VRF interface. Deletion immediately zeros out `MasterIndex` on slave interfaces in the kernel. Sequential ifindex allocation in a single apply run makes ifindex reuse extremely unlikely, and even if it occurs, name-based lookup of the active VRF ensures the index comparison behaves correctly.

4. **Lapse Rule Tracking Loss on Transient Failures**
   - **Finding:** The plan states: *“In every case where the stanza is empty, the `appliedRI[name]` entry is cleared (our claim lapses regardless of whether we issued the unbind).”*
   - **Defect:** If `LinkSetNoMaster` or `LinkByName` fails due to a transient netlink error, the binding remains in the kernel but `appliedRI[name]` is cleared anyway.
   - **Consequence:** The manager loses track of the binding, preventing it from retrying the unbind on subsequent apply runs. This violates the project's error-resilience contract (matching [A.1](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md#L182) and [A.4](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md#L308-L311)).

---

### (Q2) Ratify or Refute: Defects Introduced by Folds

We **refute** that the v4 folds are completely defect-free:

1. **Unzoned/New Tunnel MTU Bug**
   - **Finding:** The plan restricts MTU application to:
     ```go
     if reused && adopting { ... }
     ```
   - **Defect:** On a fresh tunnel creation (`mustCreate == true`), `reused` is `false`. Because [netlink.Tuntap](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L124-L130) instantiation does not specify MTU, the newly created tunnel is left at the kernel default MTU (1500).
   - **Consequence:** Downstream compiler stages do not set MTU for unzoned tunnels. A newly configured unzoned tunnel with a custom MTU (e.g. 9000) will remain incorrectly set to 1500.
   - **Remedy:** MTU configuration must be applied on creation too: `if created || (reused && adopting)`.
