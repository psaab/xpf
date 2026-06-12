I will list the permissions first to see my read/write capabilities on the worktree.
I will ask for permission to read the files in the workspace `/home/ps/git/bpfrx`.
I will view the plan file at `/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md` to understand the details of version 3.
I will search for the relevant files in the codebase using `grep_search` to verify the references.
I will view the `pkg/routing/tunnel.go` file from the worktree to see the current codebase's implementation of the tunnel manager.
I will view the next segment of `pkg/routing/tunnel.go` to understand how the wireguard branch works and how `applyWireguardTunLocked` operates.
I will view the relevant section of `pkg/daemon/daemon_apply.go` to check how step 0a binds routing-instance interface-list members.
I will grep for `collectAppliedTunnels` in `pkg/daemon/daemon_run.go` to see where it is defined.
I will view the definition of `collectAppliedTunnels` in `pkg/daemon/daemon_run.go` from lines 80 to 140.
I will grep for the definition of `TunnelConfig` and search for all occurrences across the codebase.
I will view `pkg/config/types_routing.go` around line 293 to see how `TunnelConfig` is defined.
I will search for `TunnelConfig` references within the `pkg/config` package to understand if there is any custom marshaling or validation that could be affected.
I will grep search for `TunnelConfig` across the entire codebase (excluding worktrees if possible) to identify if there are any other packages that use this type, such as dataplane or HA/sync modules.
I will view `pkg/dataplane/compiler_iface.go` around line 578 to see how `TunnelConfig` is used in compiler_iface.go.
I will search for `MTU` and `LinkSetMTU` references in `pkg/dataplane/compiler_iface.go`.
I will view `pkg/dataplane/compiler_iface.go` from lines 530 to 560 to understand the MTU application logic.
I will view lines 430 to 465 in `compiler_iface.go` to see the interface-level MTU configuration logic.
I will view lines 290 to 330 of `compiler_iface.go` to see the outer loop for the interface zone and MTU configuration.
I will view `pkg/dataplane/userspace/tunnels.go` around line 106 to verify how live interface MTU is read or handled for tunnel endpoints.
I will view `pkg/dataplane/userspace/interfaces.go` around line 368 to see how `iface.MTU` is read and populated in the snapshot.
I will list the directory contents of `pkg/` to check the package structure and see if there are any other subsystems like `ha`.
I will search for `Tunnel` in `pkg/config/compiler_interfaces.go` to see how it's parsed from the config tree.
I will view `pkg/config/compiler_interfaces.go` from lines 120 to 190.
I will view lines 200 to 280 of `pkg/config/compiler_interfaces.go` to see the parsing of unit-level tunnels.
I will list files in `/home/ps/git/bpfrx/pkg/configstore` to see how configuration is stored.
I will search for JSON/YAML marshaling or database serialization code in `store.go`.
I will list the files in `pkg/cluster` to check if there is any clustering or HA synchronization logic.
I will search for references to `TunnelConfig` or `Config` in the `pkg/cluster` package to see if cluster sync or failover logic would be impacted by the new field.
I will grep search for `Config` in `pkg/cluster/sync.go` to check how configuration is synced.
I will grep search for `collectAppliedTunnels` or `ApplyTunnels` in `pkg/cli/apply.go`.
I will view `pkg/cli/apply.go` from line 65 to 90 to see how the legacy CLI path builds `TunnelConfig`.
I will view `pkg/dataplane/compiler_iface.go` lines 680 to 715 to see how MTU inheritance or fallback works between interface-level and unit-level configurations.
I will view lines 910 to 935 in `pkg/dataplane/compiler_iface.go` to see the MTU logic for regular interfaces.
I will search for `DeepEqual` references in `pkg/config` tests to see if any tests perform direct struct comparison of config objects that could be broken by adding the `MTU` field.
I will run a grep search for `DeepEqual` across all Go tests in the `pkg/` directory.
I will search for the definition of `TunnelEndpointSnapshot` in the codebase using grep to see what fields it contains.
I will view the definition of `TunnelEndpointSnapshot` in `pkg/dataplane/userspace/protocol.go` from line 260 to 295.
I will view `pkg/routing/routing_test.go` from line 1190 to 1220 to see what `gotLinks` and `tc.wantLinks` represent.
I will view lines 680 to 726 of `pkg/routing/tunnel.go` to inspect the lock nesting structure in `GetStatus`.
I will view lines 630 to 680 of `pkg/routing/tunnel.go` to see the start of the status/list method and check its locking behavior.
I will view `pkg/routing/tunnel.go` from line 520 to 600 to check `keepaliveLoop` and its locking behavior.
PLAN-READY

### Verification of v3 Folds
*   **(F1) Entry-time `oldOwned` Snapshot:** Sound. By freezing the adoption authority in `oldOwned` at `Apply` entry, we ensure subsequent writes to `t.ownedNames` within the desired loop do not affect adoption status or cause transient MTU updates.
*   **(F2) Desired MTU on Adoption:** Sound. Setting the desired MTU only on adoption (`reused && adopting`) closes the unzoned-tunnel MTU restore hole.
*   **(F3) VRF Ownership & RI List Conflict:** Sound. Tracking `appliedRI` and unbinding only manager-bound VRFs prevents the destruction of step 0a bindings (`pkg/daemon/daemon_apply.go:218-237`).
*   **(F4) failed-AddrDel Retention:** Sound. Keeping failed-delete link-locals in `appliedAddrs` ensures they are cleaned up on a retry rather than orphaned.
*   **(F5) failed-LinkDel Retention:** Sound. Leaving failed deletes in `ownedNames` ensures retry on subsequent applies.

---

### Five Round-3 Open Questions

#### 1. MTU Precedence & `config.TunnelConfig` Consumers
*   **MTU Precedence:** `unit.MTU > 0 ? unit.MTU : ifc.MTU` is the correct precedence. It mirrors the exact logic in the zone interface compiler at [pkg/dataplane/compiler_iface.go:918-922](file:///home/ps/git/bpfrx/pkg/dataplane/compiler_iface.go#L918-L922) where unit-level settings override parent interface configurations.
*   **Consumers:**
    *   **HA Config Sync:** Configuration synchronization operates on raw configuration text ([pkg/cluster/sync.go:172-173](file:///home/ps/git/bpfrx/pkg/cluster/sync.go#L172-L173)); it does not parse or transmit programmatic `TunnelConfig` structs.
    *   **Dataplane Snapshot Builders:** The snapshot builder ([pkg/dataplane/userspace/tunnels.go:90-115](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/tunnels.go#L90-L115)) maps fields to a separate JSON-tagged `TunnelEndpointSnapshot` structure. 
    *   **Config Store:** Standard JSON serialization at [pkg/configstore/store.go:1076](file:///home/ps/git/bpfrx/pkg/configstore/store.go#L1076) is additive and backward-compatible (missing fields default to 0). No tests perform direct `reflect.DeepEqual` comparison on `TunnelConfig` or `Config` structs.

#### 2. `appliedRI` VRF Replaced by 0a-list Between Applies
*   **Sequence Trace:**
    1.  **Apply 1:** Tunnel has `routing-instance VRF_B`. `ApplyTunnels` binds it to `VRF_B` ([pkg/routing/tunnel.go:183-188](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L183-L188)) and records `appliedRI[name] = "VRF_B"`.
    2.  **Apply 2:** User removes the tunnel-stanza `routing-instance` but adds the tunnel name to the 0a list of `VRF_A` ([pkg/daemon/daemon_apply.go:218-237]).
    3.  **Execution (Apply 2):**
        *   Step 0a binds `name` to `VRF_A`.
        *   Step 1 (`ApplyTunnels`) runs. Since `tc.RoutingInstance == ""` and `appliedRI[name] == "VRF_B"`, the manager calls `LinkSetNoMaster` (unbinding from `VRF_A` which was just bound by 0a) and clears the `appliedRI` entry.
    4.  **Apply 3:** Config is unchanged. Step 0a binds it to `VRF_A`. Step 1 does nothing (since `appliedRI[name]` is now empty). It converges.
*   **Verdict:** Bind-wins-last is acceptable. Today, `Apply` completely deletes and recreates the tunnel device, permanently destroying the 0a binding without ever recovering. The new plan recovers and converges correctly starting from the subsequent apply.
*   *Refinement Recommendation:* In A.1, alongside `delete(t.appliedAddrs, name)`, execute `delete(t.appliedRI, name)` to prevent a minor string map leak when a tunnel is entirely removed.

#### 3. `LinkDel`-Failure Retention Growth Bound
*   **Trace:**
    1.  If a stale link fails to delete, `next[name] = true` keeps it in `t.ownedNames` for the next apply.
    2.  On the next apply, if the link was deleted out-of-band, the manager calls `t.ops.LinkByName(name)` ([pkg/routing/tunnel.go:179](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L179)).
    3.  Since the link is gone, `LinkByName` returns `err != nil`. The `err == nil` block containing the `LinkDel` retry and the `next[name] = true` retention is skipped.
    4.  The map entry is deleted at `delete(t.appliedAddrs, name)` and `next[name]` is *not* written.
*   **Verdict:** Sound. Stale entries whose links disappear out-of-band are cleanly pruned from `t.ownedNames` on the subsequent apply.

#### 4. Upgrade-Boot Adoption MTU Write
*   **Verdict:** Sound. On the first post-upgrade apply, the manager will adopt the existing pre-fix anchors. If the live MTU matches the desired configuration, `link.Attrs().MTU != want` is false and no write occurs. If they differ, the single `LinkSetMTU` corrects the discrepancy. Since `LinkSetMTU` on virtual TUN/TAP devices is lightweight and does not trigger physical carrier drops or driver resets, this write is harmless and operationally correct.

#### 5. Reopened r1 Closures
*   **Verdict:** None. 
    *   The transient-lookup/EEXIST race fallback (#1706) at [pkg/routing/tunnel.go:135-150](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L135-L150) is fully preserved inside the `mustCreate` block of A.3.
    *   The keepalive run-state transition and lock safety (`state.mu` nested under `t.mu`) are preserved. Since `keepaliveLoop` ([pkg/routing/tunnel.go:548-590](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L548-L590)) never acquires `t.mu`, there is no deadlock path.
