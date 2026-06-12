I will check the existing permissions to see if I can read files in the target worktree.
I will request read permission for the repo worktree `/home/ps/git/bpfrx/.claude/worktrees/1884-research` so I can read the plan and code files.
I will view the plan document under review.
I will read the entire `pkg/routing/tunnel.go` file to understand the current implementation of `tunnelManager.Apply` and related functions.
I will read `pkg/routing/iface_reuse_test.go` to understand the test setup and helper structures.
I will read `pkg/routing/routing.go` to see how `tunnelManager` is initialized and integrated with the main routing manager.
I will read the relevant parts of `pkg/daemon/daemon_run.go` to inspect the `collectAppliedTunnels` implementation and how it interacts with the tunnel manager.
I will read `pkg/daemon/daemon_apply.go` around line 259 to see the config apply sequence and how `ApplyTunnels` is invoked.
I will search for all occurrences of `ApplyTunnels` in the codebase to identify every caller.
I will search for `ClearTunnels` to see where it is used.
I will check `pkg/cli/apply.go` to see the context of the CLI's use of `ApplyTunnels`.
I will search for occurrences of `networkd` or `.network` file generation to see what interfaces are managed by systemd-networkd.
I will search in `pkg/networkd/` to see what interfaces it manages and check if GRE tunnel anchors are included.
I will read the beginning of `pkg/networkd/networkd.go` to understand how systemd-networkd configuration is managed.
I will search for occurrences of `d.networkd` in `pkg/daemon` to see which interfaces are passed to systemd-networkd.
I will search for `ManagedInterfaces` to see which interfaces are managed by the daemon and passed to networkd.
I will read a section of `pkg/dataplane/compiler_iface.go` to see if tunnel interfaces are added to `ManagedInterfaces`.
I will search for `Tunnel` in the dataplane compiler code to see if there is any tunnel-specific interface processing for systemd-networkd.
I will read `pkg/dataplane/compiler_iface.go` around line 1070 to see if tunnel interfaces are classified as `daemonOwned` and how they are processed.
I will search for occurrences of `Gretun` in the codebase to see how it is structured or utilized elsewhere.
I will search for the definition of `TunnelConfig` to see if there is an MTU field.
I will read the definition of `TunnelConfig` in `pkg/config/types_routing.go`.
I will search for `LinkSetMTU` in the codebase to see how MTU is configured for interfaces, particularly tunnels.
I will read a section of `pkg/dataplane/compiler_iface.go` to see if it sets MTU for tunnel interfaces.
I will search for `sysctl` and `/sys/` references in the Go codebase to verify if there are any sysctl adjustments on tunnel interfaces that would be impacted.
### Verdict: `PLAN-NEEDS-REVISION`

The proposed plan is a solid, clean, and highly idiomatic architectural improvement that successfully aligns GRE/IPIP tunnel management with the proven WireGuard reuse-in-place pattern. However, the plan contains **two critical design defects** and **one minor comparison trap** that must be resolved before implementation.

---

### Critical Broken Plan Scenarios

#### 1. Keepalive Down Resurrection & Permanently Stranded Up State (Q3)
Under the proposed plan, if a keepalive loop has declared a tunnel down (`state.Up == false`), it calls `LinkSetDown` to bring the interface down in the kernel. 
1. If an unrelated config change is applied, the plan retains the keepalive runner because its identity is unchanged (A.7).
2. The `Apply` loop runs and unconditionally invokes the shared tail, calling `t.ops.LinkSetUp(link)` on the reused tunnel. This resurrects the tunnel to **UP** in the kernel.
3. The keepalive runner is still running in the background. On its next check, if the probe continues to fail, the loop enters the `else` branch of `keepaliveLoop` ([pkg/routing/tunnel.go:584](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L584)):
   ```go
   if state.Up && state.Failures >= state.MaxRetries {
       // ... Bring tunnel down
   }
   ```
   Because `state.Up` is already `false`, this condition is **never met**, and `LinkSetDown` is never called. 

**Result**: The tunnel interface remains permanently stuck in an **admin UP** state in the kernel despite keepalive probes failing. 
* **Fix**: The `Apply` loop must skip calling `LinkSetUp(link)` (or explicitly keep the link down) if an existing, active keepalive runner for that tunnel is currently in the DOWN state (`!runner.state.Up`).

#### 2. Transient-Lookup Race Regression & Test Suite Failure (Q5)
The pseudo-code in A.3 misses the fallback lookup logic on `LinkAdd` failure (e.g. `EEXIST`).
1. In `pkg/routing/iface_reuse_test.go:114-152`, the unit test `TestTunnelAnchorReuseUsesExistingLink` validates the `#1706` fix.
2. It seeds an existing tunnel interface with `Index: 42` and configures `ops.hiddenUntil[name] = 1` and `ops.addExisting = true` to mock a transient race (where the initial `LinkByName` misses, but `LinkAdd` fails with `EEXIST` because the link was created concurrently).
3. Under the proposed A.3 design, the first `LinkByName` will miss, `mustCreate` will be `true`, and `LinkAdd` will run and fail with `EEXIST`. The code will log a warning and exit the loop iteration via `continue`.

**Result**: The unit test will fail, and the daemon will fail to recover/adopt tunnel anchors if it hits transient netlink lookup misses or concurrent interface creation races in production.
* **Fix**: The EEXIST fallback logic must be explicitly preserved (i.e. if `LinkAdd` returns `EEXIST`, look up the link by name once more and verify it is a `netlink.Tuntap` in `TUNTAP_MODE_TUN`).

---

### Detailed Answers to the Seven Open Questions

#### Q1: Is removing `clearLocked()` from `Apply` safe for ALL callers?
**Yes, it is safe.** 
* **Evidence**: The only production callers of `Apply` (via `ApplyTunnels`) are the daemon config apply loop ([pkg/daemon/daemon_apply.go:259](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go#L259)) and the standalone legacy CLI apply path ([pkg/cli/apply.go:83](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/cli/apply.go#L83)).
* **Reasoning**: `clearLocked()` in [pkg/routing/tunnel.go:659-674](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L659-L674) only iterates over the `t.tunnels` tracked slice. It does not perform a wild kernel scan. 
  - For the daemon: The proposed set-diff deletion loop accomplishes the exact same cleanup for removed tunnels.
  - For the CLI: `t.tunnels` is empty at startup, making `clearLocked()` a no-op anyway. 
  - `Manager.ClearTunnels` remains fully available with its legacy semantics untouched.

#### Q2: Is `MasterIndex != 0 && RI == ""` → `LinkSetNoMaster` safe on reused links?
**Yes, it is safe and will not fight systemd-networkd.**
* **Evidence**: In `pkg/dataplane/compiler_iface.go:1065-1081`, all tunnel interfaces are categorized as `daemonOwned` and explicitly skipped from being added to `result.ManagedInterfaces` (which is the input slice passed to systemd-networkd in [pkg/daemon/daemon_apply.go:501-502](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go#L501-L502)).
* **Reasoning**: Because systemd-networkd does not receive configurations for these tunnel interfaces, it does not manage them or set their VRF masters. The xpfd daemon is the sole creator and manager of tunnel anchors, meaning `LinkSetNoMaster` on empty `RoutingInstance` is safe.

#### Q3: Should `LinkSetUp` be skipped when the keepalive runner is retained and currently down?
**Yes, absolutely.**
* **Reasoning**: As demonstrated in the *Critical Broken Plan Scenarios* section above, if `Apply` calls `LinkSetUp` on a reused link while the keepalive runner is in a failed/down state, the link will remain admin UP in the kernel indefinitely because the keepalive loop will not enter its down-transition guard block.

#### Q4: Are kernel-fetched Gretun fields reliably comparable?
**No, they are not. Direct structural comparison (e.g. `reflect.DeepEqual`) will fail.**
* **Reasoning**:
  1. **IP Representation**: `net.ParseIP` returns 16-byte IPv4-mapped IPv6 representations for IPv4 addresses, whereas the kernel via netlink returns a 4-byte IPv4 address slice. Direct byte comparison fails; `net.IP.Equal` must be used.
  2. **TTL Defaulting**: If configured with `TTL: 0`, the kernel defaults it to `64`. A direct comparison `0 == 64` fails; `0` must be normalized to `64` prior to comparison.
  3. **Kernel-Generated Attrs**: The kernel populates fields like `PMtu` (defaults to `1`), `Tos`, etc. which are not part of `TunnelConfig`.
* **Fix**: Comparison must be done field-by-field on specific managed attributes: `Local` (via `net.IP.Equal`), `Remote` (via `net.IP.Equal`), `Ttl` (with 0-to-64 default normalization), `IKey`/`OKey` (for `Gretun`), and `Proto` (for `Ip6tnl`).

#### Q5: Is the retry-once collapse of `goto anchorReady` equivalent to the #1706 semantics?
**No.**
* **Reasoning**: As demonstrated in the *Critical Broken Plan Scenarios* section, removing the fallback lookup on `LinkAdd` EEXIST failure breaks the transient race protection verified by `TestTunnelAnchorReuseUsesExistingLink` ([pkg/routing/iface_reuse_test.go:114](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/iface_reuse_test.go#L114)).
* **Fix**: Retain the lookup-on-EEXIST logic inside the creation failure path.

#### Q6: Should the anchor reuse path verify TUN flags match, or is Mode==TUN sufficient?
**`Mode == TUNTAP_MODE_TUN` is sufficient (matching the WireGuard precedent).**
* **Reasoning**: `TUNTAP_ONE_QUEUE` is obsolete and dropped by the kernel. An exact flags comparison check (e.g., `tt.Flags == desiredFlags`) would fail on every run and reintroduce the tunnel flap on every config apply. If flag checking is desired as defense-in-depth, check only the `TUNTAP_NO_PI` bit (i.e. `tt.Flags & netlink.TUNTAP_NO_PI != 0`).

#### Q7: Should the anchor branch force MTU when reusing on a `wireguard → gre` flip?
**No, keep it as a documented residual.**
* **Reasoning**: `ApplyTunnels` runs before the dataplane compiler compiles zones and interface options ([pkg/daemon/daemon_apply.go:259](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go#L259) vs line 270+). 
  - `TunnelConfig` has no MTU field.
  - If the operator configured a custom MTU on the GRE interface (e.g. 1400), and `ApplyTunnels` forces MTU to 1500 on every reload because it sees it as a GRE anchor, the MTU will flap on every commit (1400 → 1500 → 1400) when the compiler runs next. 
  - Sticking to the documented residual for this extremely rare mode-flip on the same interface name is the safest approach.
