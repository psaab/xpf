I will start by listing the directory structure of the worktree to locate the plan and implementation files.
I will view the contents of the plan file `docs/research/1884-tunnel-flap/plan.md`.
I will search for the binding logic of routing instances (referred to as step 0a) in `pkg/daemon/daemon_apply.go` to understand how interfaces are normalized and bound.
I will view `pkg/daemon/daemon_apply.go` around line 194 to examine step 0a and how routing instances are bound to interfaces.
I will search for `collectAppliedTunnels` to locate its definition and see how it populates `TunnelConfig`.
I will view `collectAppliedTunnels` in `pkg/daemon/daemon_run.go` to see the current implementation.
I will search for the definition of `TunnelConfig` to see what fields it currently has.
I will view the definition of `TunnelConfig` in `pkg/config/types_routing.go`.
I will view lines 335 to 355 of `pkg/config/types_routing.go` to inspect the structure of `RoutingInstanceConfig`.
I will search for the definition of `LinuxIfName` to understand its conversion logic.
I will view `pkg/config/types.go` around line 12.
I will search for `Tunnel` in the `pkg/config` package to see where tunnel config names are populated.
I will view lines 300 to 330 in `pkg/config/types.go` to see how tunnel interface names are mapped and generated.
I will view `pkg/config/types.go` from line 150 to 225 to understand how tunnel interface names are resolved.
I will search for occurrences of `Name` being assigned on `TunnelConfig` or where tunnel configs are instantiated, to see how the name is generated during config parsing.
I will search for occurrences of `TunnelConfig` in `pkg/config` to find where the parser builds these objects and assigns their names.
I will view the tunnel interface compilation logic in `pkg/config/compiler_interfaces.go` around lines 147 and 233.
I will search for the definition of `BindInterfaceToVRF` to see how it handles interface name translation.
I will view `pkg/routing/vrf.go` from line 110 to 160 to see the implementation of `BindInterfaceToVRF`.
I will search for VRF binding calls inside `pkg/routing/tunnel.go` to see how the tunnel manager binds tunnel interfaces.
I will search for `Interfaces` population in the routing compiler `pkg/config/compiler_routing.go` to see if interface names are modified during configuration parsing/compilation.
I will view `pkg/config/compiler_routing.go` around line 297 to see how routing-instance interfaces are compiled.
I will search for `ResolveKernelIfName` usage in the `pkg/daemon` package to see if it is used elsewhere for name resolution.
I will view `pkg/daemon/daemon_dhcp.go` around line 176 to see how interface names are resolved in the DHCP manager.
I will view `go.mod` to check the version of the netlink library.
I will view the WireGuard VRF binding logic in `pkg/routing/tunnel.go` around line 479 to understand its current behavior.
I will view the VRF binding logic in the GRE/IPIP tunnel manager implementation in `pkg/routing/tunnel.go` around line 184.
I will view the non-anchor VRF binding logic in `pkg/routing/tunnel.go` around line 293.
I will search for the `"vrf-"` prefix in the `pkg/routing` package to verify that VRF devices are consistently prefixed with `"vrf-"`.
I will view `pkg/routing/tunnel.go` from line 230 to 280 to see how legacy (non-anchor) tunnels are currently created and if they set the MTU.
I will search for `LinkSetMTU` in `pkg/dataplane` to see where and under what conditions the compiler stage sets the interface MTU.
I will view `pkg/dataplane/compiler_iface.go` from line 420 to 470 to understand how MTU reconciliation is performed for interfaces in the compiler.
I will view `pkg/dataplane/compiler_iface.go` from line 380 to 420 to check the loop context for interface MTU.
I will search for zone attachment logic in the compiler to see if all interfaces are required to be zoned.
I will view `pkg/dataplane/compiler_iface.go` around line 351 to see the context of the first `LinkSetMTU` call.
I will view `pkg/dataplane/compiler_iface.go` around line 553 to see the third `LinkSetMTU` call.
I will search for the keepalive runner state structures and mutexes in `pkg/routing/tunnel.go`.
I will view lines 60 to 75 of `pkg/routing/tunnel.go` to inspect the keepalive structure definitions.
I will search for `KeepaliveState` structure definition in `pkg/routing/tunnel.go`.
I will view the `KeepaliveState` definition in `pkg/routing/tunnel.go` around line 43.
I will view the current address reconciliation logic for WireGuard in `pkg/routing/tunnel.go` around line 430 to verify the link-local behavior.
I will view the keepalive initialization logic in `pkg/routing/tunnel.go` around line 533 to check the default values.
PLAN-NEEDS-REVISION

### Q1: RIListMember Population, Normalization Mismatch, and Stage Reordering

#### 1. The Normalization / Naming Mismatch (Unit N > 0 Tunnels)
There is a naming mismatch between the Linux kernel device names for unit N > 0 tunnels and how step 0a normalizes interface list references.
* **Kernel Naming:** In [pkg/config/compiler_interfaces.go:229-232](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/compiler_interfaces.go#L229-L232), unit N > 0 tunnels append `"u"` followed by the unit number (e.g., `gr-0/0/0` unit 1 becomes `gr-0-0-0u1`):
  ```go
  linuxName := LinuxIfName(ifName)
  if unitNum > 0 {
      linuxName = linuxName + "u" + strconv.Itoa(unitNum)
  }
  ```
* **Step 0a Normalization:** In [pkg/daemon/daemon_apply.go:222-228](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go#L222-L228), step 0a normalizes interfaces in `ri.Interfaces` using a simple `LinuxIfName` translation and stripping `.0` suffixes:
  ```go
  linuxName := config.LinuxIfName(ifaceName)
  if strings.HasSuffix(linuxName, ".0") {
      linuxName = strings.TrimSuffix(linuxName, ".0")
  }
  ```
  If the Junos config lists `gr-0/0/0.1` under `routing-instances <ri> interface`, step 0a converts it to `gr-0-0-0.1`.

#### Consequence:
1. **0a Bind Failure:** Step 0a attempts to bind `gr-0-0-0.1` to the VRF, which fails with an interface-not-found error because the actual device in the kernel is named `gr-0-0-0u1`.
2. **Scan Failure (`RIListMember` is empty):** The plan's proposed scan in `collectAppliedTunnels` replicates step 0a's exact normalization. It yields `gr-0-0-0.1` for `gr-0/0/0.1`, which fails to match `tc.Name` (`gr-0-0-0u1`). Thus, `tc.RIListMember` remains empty.
3. **VRF Unbinding on Stanza-to-List Transition:** If an operator moves a unit N > 0 tunnel from a tunnel-stanza `routing-instance` to a routing-instance `interface` list, the tunnel manager evaluates `tc.RoutingInstance == ""` and `tc.RIListMember == ""` (due to the empty scan result) as true. It will then explicitly **unbind** `gr-0-0-0u1` from its VRF, leaving the tunnel completely outside its intended VRF.

#### Recommendation:
Both step 0a and the `collectAppliedTunnels` scan should resolve interface names using `cfg.ResolveKernelIfName(ifaceName)` ([pkg/config/types.go:169](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/types.go#L169)) instead of crude string stripping. `ResolveKernelIfName` correctly maps `gr-0/0/0.1` to `gr-0-0-0u1` via `TunnelNameMap()`.

#### 2. Reorder Rejection Soundness
Rejecting the reorder of daemon apply stages is **sound**. Changing the order of entire apply stages has a high blast radius since step 0a binds various other interfaces (physical, VLANs, RETHs) that depend on VRFs being initialized first. Moreover, reordering would not resolve the name mismatch anyway; step 0a would still fail to bind `gr-0-0-0u1` under the name `gr-0-0-0.1`.

---

### Q2: Defects in Folds / Re-opened Closures

The proposed folds are generally robust, but there is one minor residual defect in the MTU path:

#### 1. Unzoned Tunnel MTU Changes
The plan specifies:
> "Owned reuse (adopting == false) NEVER touches MTU — ongoing config-MTU reconcile stays owned by the compiler stage..."

However, the compiler stage in [pkg/dataplane/compiler_iface.go](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/compiler_iface.go) only iterates over interfaces assigned to security zones. If a tunnel is **unzoned** and already owned (reused):
* The compiler stage will not reconcile its MTU because it is unzoned.
* The tunnel manager will not reconcile its MTU because `adopting` is false.
* **Result:** Modifying the MTU of an unzoned, reused tunnel in configuration will be ignored. Since unzoned interfaces do not forward traffic in the dataplane anyway, this is a minor limitation, but worth noting.

#### 2. Verification of Other Folds:
* **`vrf-` Prefix Lookup Bug:** Correctly fixed. Resolving `"vrf-" + appliedRI[name]` aligns with the naming schema used in [pkg/routing/vrf.go:127](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/vrf.go#L127).
* **Lapse-on-Transient-Failure:** The claim-lapse rule ensures that transient netlink failures (such as `LinkByName` or `LinkSetNoMaster` errors) preserve the `appliedRI` claim, enabling automatic retries in subsequent apply runs.
* **Keepalive Normalization & Thread-Safety:** Normalizing `maxRetries <= 0` to `3` prior to comparison correctly prevents unnecessary restarts. Reading `state.Up` under `state.mu` lock is thread-safe.
* **WireGuard Extraction Hygiene:** Passing a `nil` `applied` map to `reconcileLinkAddrsLocked` correctly preserves the WireGuard branch's pre-existing behavior of skipping link-local deletions.
