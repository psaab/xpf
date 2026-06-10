I will locate and view the plan file `docs/research/1827-multiwan/plan.md` to start analyzing it.
I will run a command to find the location of the plan or any relevant files for issue 1827.
I will verify if the file `docs/research/1827-multiwan/plan.md` exists and view its contents if it does.
I will run a command to search for any files or folders containing "1827" in their name or path.
I will check the files and directories inside `docs/` to see if `docs/research` exists.
I will list the directories and files under `.claude/codex-review/workflows/` to locate the plan files.
I will list the active git worktrees.
I will check if `docs/research/1827-multiwan/plan.md` is present in the `research-1827-multiwan` worktree.
I will view the plan file from the `research-1827-multiwan` worktree to read its contents and plan my analysis.
I will view `pkg/rpm/rpm.go` to examine the current implementation of the RPM probe manager and the fake ICMP ping.
I will view `pkg/dataplane/userspace/routes.go` to check how the userspace FIB is constructed.
I will view `pkg/daemon/daemon_apply.go` starting around line 700 to verify the instance-type forwarding and FRR table divergence.
I will search for `applyConfig` references in `pkg/daemon/daemon_run.go` using grep to check the runtime feed re-apply precedent.
I will view `pkg/daemon/daemon_run.go` from line 580 to 620 to check the dynamic feeds re-apply precedent and the current RPM lifecycle.
I will search for the definition of `applyConfig` to see how synchronization/locking is handled.
I will view `pkg/daemon/daemon_apply.go` from line 60 to 175 to understand how config application serialization/locking is done.
I will view `pkg/frr/manager.go` to inspect the emission-order contract and how static routes/instances are applied to FRR.
I will view `pkg/config/compiler_routing.go` from line 150 to 250 to check the parser/compiler implementation for `qualified-next-hop` and routing preferences.
I will search for the definition of `NextHopEntry` to see if there is any preference field.
I will view `pkg/config/types_routing.go` around line 94 to check the fields of `NextHopEntry`.
I will search the codebase for `collectDHCPRoutes` to see where else DHCP-learned routes are used or if they are passed to the dataplane snapshot.
I will view `pkg/daemon/daemon_flow.go` to understand how DHCP leases and routes are collected and whether they affect the dataplane FIB.
I will search for the definition of `generateStaticRoute` in `pkg/frr/` to see how it uses the VRF name parameter.
I will view `pkg/frr/config_render.go` from line 80 to 140 to see how `generateStaticRoute` is implemented.
PLAN-NEEDS-REVISION

### 1. Verification of Plan Claims Against Workspace Code

*   **RPM Fake ICMP Ping:** Confirmed. [pkg/rpm/rpm.go:294-313](file:///home/ps/git/bpfrx/pkg/rpm/rpm.go#L294-L313) shows `probeICMP` uses TCP connect to port 7 (`ip4:icmp`) and falls back to a UDP dial to port 33434. It does not send or receive real ICMP Echo packets.
*   **Config-Derived FIB:** Confirmed. [pkg/dataplane/userspace/routes.go:14-146](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/routes.go#L14-L146) (`buildRouteSnapshots`) constructs the userspace FIB snapshot exclusively from the active static configuration (`cfg.RoutingOptions.StaticRoutes`, `ri.StaticRoutes`, etc.), connected interfaces, and netlink rules. Dynamic routes from FRR or the kernel never enter this helper FIB.
*   **Forwarding VRF Divergence:** Confirmed. [pkg/daemon/daemon_apply.go:761-766](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L761-L766) sets `vrfName = ""` (default routing table) for instances of type `"forwarding"` when configuring FRR, whereas the userspace snapshot builder in [pkg/dataplane/userspace/routes.go:77](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/routes.go#L77) groups them under `<ri>.inet.0`.
*   **Feeds Re-Apply Precedent:** Confirmed. [pkg/daemon/daemon_run.go:588-596](file:///home/ps/git/bpfrx/pkg/daemon/daemon_run.go#L588-L596) calls `d.applyConfig(activeCfg)` within a feed update callback.
*   **FRR Emission-Order Contract:** Confirmed. [pkg/frr/manager.go:174-189](file:///home/ps/git/bpfrx/pkg/frr/manager.go#L174-L189) documents the explicit order of section configuration emission.
*   **Qualified Next-Hop Preference Ignored:** Confirmed. [pkg/config/compiler_routing.go:170-180](file:///home/ps/git/bpfrx/pkg/config/compiler_routing.go#L170-L180) and [pkg/config/compiler_routing.go:222-235](file:///home/ps/git/bpfrx/pkg/config/compiler_routing.go#L222-L235) parse the `qualified-next-hop` address and interface but completely ignore nested `preference` values, and the target struct [pkg/config/types_routing.go:94-97](file:///home/ps/git/bpfrx/pkg/config/types_routing.go#L94-L97) (`NextHopEntry`) has no preference field.

---

### 2. Numbered Review Findings

#### Finding 1 (Critical): Dataplane-to-Controlplane Route Metric/Distance Divergence
*   **Evidence:** [pkg/dataplane/userspace/routes.go:14-146](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/routes.go#L14-L146) and [pkg/config/types_routing.go:94-97](file:///home/ps/git/bpfrx/pkg/config/types_routing.go#L94-L97)
*   **Reason:** The userspace `RouteSnapshot` has no administrative distance/preference field. The plan proposes that the Go builder replaces a prefix with the preferred-route next-hop at build time. However, if a preferred route is installed with a higher distance (e.g., preference 10) than a primary static route (preference 5), Zebra will select the primary route as active. Meanwhile, the Go snapshot builder will blindly override the entry with the preferred route. This will cause the dataplane to forward packets to the backup next-hop while the control plane/kernel forwards to the primary next-hop.
*   **Concrete Fix:** Add a `Preference` field to `RouteSnapshot` to let the dataplane perform distance-aware resolution, or write a metric-aware resolution helper in Go that mimics Zebra's routing active-selection rules before producing the final snapshot.

#### Finding 2 (Critical): Non-Deterministic Egress for Multiple Same-Prefix Overlay Routes
*   **Evidence:** [pkg/dataplane/userspace/routes.go:28-53](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/routes.go#L28-L53) and [pkg/config/types_routing.go:94-97](file:///home/ps/git/bpfrx/pkg/config/types_routing.go#L94-L97)
*   **Reason:** If multiple policies or overlay routes target the same prefix (e.g., default route `0.0.0.0/0` targeted by different probe failure rules), Go's build-time prefix override map iteration will be non-deterministic. Without a preference metric to resolve same-prefix routes in Go, the snapshot builder will randomly choose one next-hop while FRR/Zebra chooses the route with the lowest metric.
*   **Concrete Fix:** Implement a strict preference sorting pass in Go's snapshot override builder to resolve same-prefix conflicts according to administrative distance before writing to the snapshot.

#### Finding 3 (High): Blocked Control-Plane Semaphore via `applyConfig` Flap-Storm
*   **Evidence:** [pkg/daemon/daemon_apply.go:68-74](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L68-L74)
*   **Reason:** Triggering a full `applyConfig` on every probe state transition is extremely heavyweight. It locks the global `d.applySem` semaphore to regenerate networkd settings, reconfigure interfaces via networkctl, and run `systemctl reload frr` (which calls `frr-reload.py` to diff configurations). Back-to-back transitions or multiple failing probes will serialize under `d.applySem`, starving the control plane, causing concurrent operator commits to time out (returning 503 errors via `commitAndApply`), and spiking CPU utilization.
*   **Concrete Fix:** Implement Path D-delta: perform narrow-delta route updates by pushing incremental routes directly via vtysh and updating the userspace FIB snapshot with a targeted snapshot diff update, bypassing the slow networkd reload and full FRR config reload.

#### Finding 4 (High): Standby Node Probe Outage Window on HA Takeover
*   **Evidence:** [pkg/daemon/daemon_apply.go:760](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L760)
*   **Reason:** Sourcing probes from a shared WAN VIP means the standby node cannot probe successfully (since it doesn't own the VIP). On takeover, the node becomes primary, treats the state as "unknown" (installing the baseline config with the dead primary route), and triggers a re-probe. This introduces an outage window of at least one probe cycle (e.g., 5-15 seconds) during failover.
*   **Concrete Fix:** Source RPM probes from node-local physical interface IPs instead of the VIP. This allows the standby node to maintain an accurate health state of both WAN links and apply the correct routing overlay immediately upon takeover.

#### Finding 5 (Medium): Forwarding VRF Divergence Breaks PR-1 Routing-Instance Target
*   **Evidence:** [pkg/daemon/daemon_apply.go:761-766](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L761-L766) vs [pkg/dataplane/userspace/routes.go:77](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/routes.go#L77)
*   **Reason:** Routing instances of type `"forwarding"` render routes under the default table in FRR config (`vrfName = ""`), but under `<ri>.inet.0` in the userspace dataplane snapshot. Although the plan defers this divergence fix to PR-2, any PR-1 `ip-monitoring` preferred-routes targeting a forwarding routing-instance will fail to resolve because their destination tables differ.
*   **Concrete Fix:** Move the forwarding routing instance divergence fix from PR-2 into a mandatory prerequisite task for PR-1.

#### Finding 6 (Medium): Bundling Real-ICMP Echo Prober in PR-1
*   **Evidence:** [pkg/rpm/rpm.go:294-313](file:///home/ps/git/bpfrx/pkg/rpm/rpm.go#L294-L313)
*   **Reason:** The real ICMP echo prober requires a raw socket implementation and socket option binding, which is a major behavioral change. Bundling this with the ip-monitoring config parser, engine, metrics/overlay builder, and show commands makes PR-1 too large and risky.
*   **Concrete Fix:** Split the real ICMP echo prober and the RPM lifecycle fix (`d.rpm.Apply` on config commit) into a separate, independent prerequisite PR.

#### Finding 7 (Low): Egress Path Pinning for Real Traffic
*   **Evidence:** [pkg/rpm/rpm.go:21-45](file:///home/ps/git/bpfrx/pkg/rpm/rpm.go#L21-45)
*   **Reason:** Auto-installing a `/32` route for the probe target via `next-hop` pins all traffic to that target via that interface. If the probe target is also a destination for real transit traffic (e.g. a public DNS server like `1.1.1.1`), that real transit traffic will be silently pinned and forced out of that specific interface, bypassing PBR policy steering.
*   **Concrete Fix:** Restrict the probe next-hop pin route lookup strictly to the prober process (e.g. using socket policy routing rules or network namespaces) instead of installing it in the global table.

---

### 3. Answers to Section 12 Open Questions

1.  **Standby probe semantics:** Probes must run continuously on both nodes. Sourcing probes from node-local physical IPs (instead of VIPs) prevents standby node probe failures. This ensures both nodes have accurate health status of all uplinks at all times, enabling instantaneous failover upon takeover with zero probe-cycle latency.
2.  **preferred-metric → FRR admin distance:** Yes, mapping preferred-metric to FRR distance is correct. However, because the Go snapshot builder lacks metric awareness (Finding 1), preferred routes can cause control-plane/dataplane route divergence.
3.  **Real-ICMP behavior change:** Real-ICMP should be separated into its own prerequisite PR. It is a major behavioral change that can immediately fail existing, invalid ping target configs on master.
4.  **Re-apply per transition:** Actuating failover via a full `applyConfig` reload is rejected. It will cause CLI commit timeouts and control-plane lockups. A delta-based route update mechanism (incremental vtysh routes + narrow-delta snapshot updates) is required.
5.  **Same-prefix override at build time:** Blindly overriding prefixes in Go is highly problematic. Multiple active policies targeting the same prefix will result in non-deterministic route snapshot creation (Finding 2).
6.  **Pin routes for `next-hop`:** Auto-installing the /32 pin route is correct, but it must be isolated to the prober process to prevent hijacking real transit traffic targeting the same destination IP.
7.  **PR-2's FBF divergence:** The FBF forwarding instance mismatch must be solved as a PR-1 precondition. Deferring it to PR-2 breaks any `ip-monitoring` policy targeting a forwarding instance in PR-1.
