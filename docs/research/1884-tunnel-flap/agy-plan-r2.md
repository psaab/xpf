I will list the available permissions and then check the repository structure to locate the files relevant to the plan and source code.
I will request permission to read files in the repository directory `/home/ps/git/bpfrx` so that I can use standard file viewing and searching tools directly on the workspace.
I will read the v2 plan file `docs/research/1884-tunnel-flap/plan.md` to understand the proposed implementation details.
I will list the contents of the `docs/research/1884-tunnel-flap/` directory to see all context files.
I will search for references to `ApplyTunnels` in the source code to locate the relevant files and verify their file paths.
I will read the initial lines of `pkg/routing/tunnel.go` to understand the existing tunnel apply/creation logic.
I will read the remaining lines of `pkg/routing/tunnel.go` to have the complete implementation context.
I will read the lines around line 259 in `pkg/daemon/daemon_apply.go` to analyze the exact execution order inside the configuration apply process.
I will search for compilation or interface compiler operations downstream of `ApplyTunnels` in `pkg/daemon/daemon_apply.go`.
I will do a case-insensitive search for `compiler` in `pkg/daemon/daemon_apply.go` to find where interface or dataplane compilation happens.
I will perform a case-insensitive search for `compile` in `pkg/daemon/daemon_apply.go` to locate compilation stages.
I will read the lines 420 to 500 of `pkg/daemon/daemon_apply.go` to see the compilation step details.
I will grep for `ApplyConfig` in the repository to locate its implementation and see where the interface compiler logic is executed.
I will read the `ApplyConfig` implementation in `pkg/dataplane/apply.go` to see the compiler execution sequence.
I will search for the definition of the `Compile` method on the dataplane `Manager` to see what steps compile does.
I will read lines 290 to 350 of `pkg/dataplane/compiler.go` to examine the compilation process.
I will grep for the definition of `CompileConfig` to understand where interface parameters like MTU are compiled.
I will read lines 145 to 220 of `pkg/dataplane/compiler.go` to see how `CompileConfig` handles interface options, specifically MTU configuration.
I will search for `LinkSetMTU` inside `pkg/dataplane/compiler_iface.go` to see the MTU settings.
I will read `pkg/dataplane/compiler_iface.go` around line 351 to see when it sets the MTU on interfaces.
I will read `pkg/dataplane/compiler_iface.go` around line 452 to see the second `LinkSetMTU` call.
I will read `pkg/dataplane/compiler_iface.go` around line 553 to see the third `LinkSetMTU` call.
I will search for the definition of `compileZones` to see if it is in `pkg/dataplane/compiler_iface.go` or another file.
I will read `pkg/dataplane/compiler_iface.go` around line 218 to verify how the interfaces are processed inside `compileZones`.
I will view the next block of lines in `compileZones` to see how interfaces are retrieved and processed.
I will read lines 480 to 535 of `pkg/dataplane/compiler_iface.go` to see how non-VLAN interfaces are processed and if there is any path for them outside of zones.
I will search for any early return statements in `pkg/daemon/daemon_apply.go` between lines 260 and 456 to see if a failure in intermediate steps can abort the apply config run before the compiler stage is reached.
I will search for the DHCP lease handler in `pkg/daemon/daemon_dhcp.go` or search for `ApplyTunnels` calls there to see if it bypasses the compiler stage.
I will view `pkg/daemon/daemon_dhcp.go` around line 82 to see how DHCP lease events trigger config changes.
I will search for the definition of `applyConfig` to verify its implementation and check if it runs the entire apply sequence including `applyConfigLocked`.
I will view `pkg/daemon/daemon_apply.go` around line 66 to see the outer `applyConfig` handler structure.
I will view `pkg/cli/apply.go` to see how the standalone CLI tool applies configuration and if it also runs the compiler stage.
I will search for the definition of `TunnelConfig` and `InterfaceConfig` in the `pkg/config` directory to check if MTU is available in `TunnelConfig`.
I will read `pkg/config/types_routing.go` around line 293 to inspect the fields in `TunnelConfig`.
I will search for `Gretun` in the source code to see how netlink structs are constructed and used.
I will view the `go.mod` file to verify the `netlink` library version being used.
I will search for `slowpath.rs` in the repository to check the Rust-side XDP/TUN setup details.
I will search for `IFF_` flags or `open_tun` in `userspace-dp/src/slowpath.rs` to verify the flags used on the Rust side.
I will read lines 1050 to 1090 of `pkg/dataplane/compiler_iface.go` to verify how tunnel interfaces are treated with respect to systemd-networkd management and confirm the VRF ownership invariant.
I will search for `BindInterfaceToVRF` to check its implementation and verify how it interacts with the VRF binder.
I will view `pkg/routing/vrf.go` around line 126 to see the exact implementation of `BindInterfaceToVRF`.
PLAN-READY

### 1. Verification of Round 1 Criticals

*   **Critical 1: Keepalive-down resurrection via `state.Up` gate (A.7 skip-LinkSetUp-on-down-runner) — CLOSED**
    *   **Trace:** In the current implementation of `keepaliveLoop` ([tunnel.go:587-596](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L587-L596)), bringing the link admin down on probe failures is gated strictly on `state.Up && state.Failures >= state.MaxRetries`. Once `state.Up` becomes `false`, subsequent failures will not re-issue `LinkSetDown`.
    *   **Resolution:** In the proposed v2 plan, skipping the shared tail's `LinkSetUp` when the retained runner has `state.Up == false` ensures that if a config apply occurs while the runner is down, it does not bring the link up. Since the link remains down, the keepalive runner does not miss the down transition when probes continue to fail.

*   **Critical 2: Dropped `LinkAdd-EEXIST` fallback breaking `#1706` hiddenUntil race tests — CLOSED**
    *   **Trace:** The `#1706` race tests in [iface_reuse_test.go](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/iface_reuse_test.go) require that when `LinkAdd` returns an `EEXIST` error (due to a transient-lookup race), the manager performs a single re-lookup to adopt the kernel-fetched link.
    *   **Resolution:** The v2 plan (A.3) preserves this by doing exactly one re-lookup via `t.ops.LinkByName(tc.Name)` when `LinkAdd` fails. If `anchorReusable(existing)` passes, it adopts the link (`link = existing`) and continues. If it is not reusable or doesn't exist, it logs a warning and continues without an infinite loop.

---

### 2. Pressure-Testing New v2 Mechanisms

*   **`ownedNames` desired-set diff (A.1):**
    *   **Analysis:** No issues found. Because `Apply` ([tunnel.go:94-310](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L94-L310)) does not return early on individual tunnel errors (it logs warnings and calls `continue`), `ownedNames` is guaranteed to be updated to the new `desired` set on every apply. When `Clear()` / `clearLocked()` is called, it correctly clears `ownedNames` and `appliedAddrs`.
*   **`applied-set` link-local rule (A.4):**
    *   **Analysis:** Structurally sound. To prevent a nil map panic when the WG branch reuses the helper (since the WG branch passes a `nil` applied-set sentinel), the helper's check must be guarded as: `if applied != nil && applied[key]`.
*   **MTU-reset-on-adoption-only (A.3):**
    *   **Analysis:** Structurally sound. Resets to default `1500` only on adoption (when `adopted` is true), which happens at most once per daemon boot/adoption. This resolves the WG-to-GRE mode-flip MTU leak without causing per-commit MTU fight.
*   **`NO_PI` + persist reuse checks (A.3):**
    *   **Analysis:** Structurally sound. The Rust dataplane opens the TUN device using `IFF_TUN | IFF_NO_PI` at [slowpath.rs:355](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/userspace-dp/src/slowpath.rs#L355). Verifying `Flags & TUNTAP_NO_PI != 0` and `NonPersist == false` on the existing link prevents attaching to incompatible or ephemeral TUNs. Ignoring `TUNTAP_ONE_QUEUE` is correct as the kernel does not report it in readback.
*   **Keepalive identity normalization (A.7):**
    *   **Analysis:** Structurally sound. Defaulting `maxRetries <= 0` to `3` before comparison avoids comparing a config `0` against a running `3`, preventing runner restarts on every commit.
*   **VRF master ownership invariant (A.5):**
    *   **Analysis:** Verified. All tunnel interfaces are marked as `daemonOwned` at [compiler_iface.go:1072-1081](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/compiler_iface.go#L1072-L1081) and are completely excluded from networkd configuration generation or unmanaged clean up. Adding `LinkSetNoMaster` to `linkOps` to unbind VRFs when `RoutingInstance == ""` is correct and has no lock ordering issues since it is a pure netlink call.

---

### 3. Answers to Plan Section 11 Open Questions

*   **Q1: Is `adopted ∧ MTU≠1500 ⇒ LinkSetMTU(1500)` the right ownership boundary, or does any path exist where the compiler stage does NOT follow in the same `applyConfig` run?**
    *   **Answer:** Yes, it is the correct boundary. The compiler stage is guaranteed to execute in the same apply run.
    *   **Evidence:** In the daemon apply loop [daemon_apply.go:259](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go#L259) calls `d.routing.ApplyTunnels` and [daemon_apply.go:457](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go#L457) calls `d.dp.ApplyConfig` within `applyConfigLocked`. In the standalone CLI path [apply.go:83](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/cli/apply.go#L83) calls `c.routing.ApplyTunnels` and [apply.go:93](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/cli/apply.go#L93) calls `c.dp.Compile` within `applyToDataplane`. Both paths execute these functions sequentially with no early exit or return statements in between. Note: if a tunnel is not assigned to a security zone, the compiler MTU stage at [compiler_iface.go:218](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/compiler_iface.go#L218) will not touch it, but interfaces not in any zone are inactive anyway.

*   **Q2: Any hole where a CONFIGURED fe80 is absent from `appliedAddrs` at removal time other than the documented daemon-restart residual? Is best-effort acceptable?**
    *   **Answer:** Yes, best-effort is acceptable. The only other case where this happens is if `AddrAdd` transiently fails during the apply that introduced it. If `AddrAdd` failed, the address was never added to the kernel, so there is no kernel address to clean up anyway. On the next successful apply, the address will succeed and be registered in `appliedAddrs`.

*   **Q3: Does skipping `LinkSetUp` interact badly with a tunnel whose link someone ELSE downed (operator `ip link set down`) while the keepalive runner is up — i.e. should the skip be keyed strictly on runner-down, as proposed?**
    *   **Answer:** No. Keying the skip strictly on `state.Up == false` is correct. If the runner is UP (`state.Up == true`) but the link is manually downed, `Apply` will call `LinkSetUp` and bring it back up. This is standard control plane behavior (overriding manual out-of-band state changes with configuration). If the runner is DOWN (`state.Up == false`), `Apply` skips `LinkSetUp`, preventing the keepalive-down resurrection bug.

*   **Q4: Any caller sequence where `ownedNames` goes stale relative to the kernel in a way that deletes a link the manager should not own?**
    *   **Answer:** No. In the daemon path, `Apply` overwrites `ownedNames` with the desired set unconditionally at entry, and `Clear()` clears it completely. In the CLI standalone path, the manager is instantiated fresh each run, so `ownedNames` starts empty and deletes nothing.

*   **Q5: Any remaining kernel-normalization traps in Gretun/Iptun/Ip6tnl readback beyond the listed field set?**
    *   **Answer:** No. The plan in A.6 explicitly lists the compared fields (`Local`, `Remote`, `Ttl`, `IKey`/`OKey`, and `Proto`) and explicitly excludes non-comparable/kernel-mutated fields (such as `PMtu`, `Tos`, `Flags`, `EncapLimit`, `EncapType`, and `EncapFlags`). Comparing only config-driven attributes avoids any netlink readback traps.

*   **Q6: Is the one-time adoption MTU bounce acceptable for FRR/dataplane consumers, or must adoption read the desired MTU?**
    *   **Answer:** Yes, it is acceptable. The bounce is a one-time, brief transient state during daemon boot/adoption. Furthermore, `TunnelConfig` ([types_routing.go:293](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/types_routing.go#L293)) does not carry an MTU field (MTU is configured on interface/unit configs in [compiler_iface.go:452,553](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/compiler_iface.go#L452)). Passing the desired MTU into the routing package would require major refactoring of public APIs, which is not justified for a brief boot-time bounce.

---

### Summary of Review
The Plan v2 is robust, correctly closes both Round 1 critical issues, and addresses all potential failure modes and open questions with sound reasoning. No blocking issues or regressions were found. The plan is ready for implementation. Plan verdict: **PLAN-READY**.
___
I have completed the adversarial review of the Round 2 plan for xpf issue #1884 without modifying any files in the workspace. All open questions have been answered using code references from the worktree. Let me know if you need any additional analysis or further verification!
