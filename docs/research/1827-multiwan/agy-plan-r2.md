PLAN-READY

### 1. Verification of v2 Resolutions of r1 Findings

*   **F1/F2 (Distance Divergence + Same-Prefix Non-Determinism):** Fully Resolved.
    *   **Mechanism:** Go-side winner selection picking a single active preferred route based on `preferred-metric` and lexicographical policy name.
    *   **FRR Evidence:** [pkg/frr/config_render.go:103-104](file:///home/ps/git/bpfrx/pkg/frr/config_render.go#L103-L104) and [pkg/frr/config_render.go:147-148](file:///home/ps/git/bpfrx/pkg/frr/config_render.go#L147-L148) demonstrate that FRR static routes carry administrative distance/preference (`sr.Preference`). By injecting a single winner at distance 1, it defeats the default static routes (defaulting to distance 5 in [pkg/config/types_routing.go:104](file:///home/ps/git/bpfrx/pkg/config/types_routing.go#L104)).
    *   **Dataplane Evidence:** [pkg/dataplane/userspace/routes.go:14-146](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/routes.go#L14-L146) (`buildRouteSnapshots`) contains no distance-resolution logic and only takes the first next-hop in Rust (`userspace-dp/src/afxdp/forwarding_build/fib.rs:161-163`). Replacing the entire prefix entry in the snapshot with the single winner ensures perfect control-to-dataplane alignment.
*   **F3 (Flap-Storm Starvation):** Fully Resolved.
    *   **Mechanism:** Routes-only actuator under the global apply semaphore, utilizing a 1s debounce timer, a single in-flight actuation, and config-hash-gated RPM re-apply.
    *   **Semaphore Evidence:** [pkg/daemon/daemon_apply.go:69/89/119/139](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L69) and [pkg/daemon/daemon_run.go:379/625/980](file:///home/ps/git/bpfrx/pkg/daemon/daemon_run.go#L379) demonstrate that all config applications serialize via `d.applySem`.
    *   **FIB Generation Evidence:** [pkg/dataplane/userspace/manager.go:918](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/manager.go#L918) and [pkg/dataplane/userspace/manager.go:968](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/manager.go#L968) verify the lightweight `bump_fib_generation` control message path.
    *   **Path D-delta Acceptance:** Deferring incremental vtysh (Path D-delta) is highly acceptable. Because failover detection takes 6-15s (successive-loss 3 on a multi-second probe interval), saving 1s of reload latency does not justify the risk of maintaining a separate incremental vtysh synchronization loop.
*   **F4 (Standby Outage Window):** Rejection Rationale Accepted.
    *   **Evidence:** [pkg/daemon/direct_vip_ownership_test.go:16-19](file:///home/ps/git/bpfrx/pkg/daemon/direct_vip_ownership_test.go#L16-L19) asserts that local secondary nodes never own VIPs. Member interfaces under a RETH bundle lack IP addresses and cannot source traffic. Local out-of-band management IP interfaces cannot reach WAN targets. Standby probing is structurally impossible under the current codebase's cluster network model.
*   **F5 (FBF Forwarding Instance Mismatch):** Fully Resolved.
    *   **Evidence:** [pkg/daemon/daemon_apply.go:761-766](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L761-L766) (renders forwarding statics into default table `""`) vs [pkg/dataplane/userspace/routes.go:77](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/routes.go#L77) (renders forwarding under `<ri>.inet.0`). Staging commit-time rejection in PR-1b makes this known divergence unreachable.
*   **F6 (PR Split):** Split into PR-1a and PR-1b is correct.
*   **F7 (Pin Routes Priority):** Checked.
    *   **Evidence:** [pkg/routing/rules.go:26/37/31](file:///home/ps/git/bpfrx/pkg/routing/rules.go#L26) shows next-table rules at priority 100, PBR at 31000, and rib-group at 33000. Priority range `50-99` is vacant and safe for probe pin rules.

---

### 2. Answers to Section 12 Open Questions

1.  **Winner-resolution parity:** Acceptable. Since FRR statics have no metric knob, Go-side resolution of a single distance-1 static matches kernel/dataplane by construction.
2.  **Actuator extraction risk:** Sufficient, provided the active overlay is passed to `applyConfigLocked` (see Finding 2).
3.  **Pin-route plumbing:** vacuously safe. Priority range `50-99` successfully bypasses next-table and PBR. Marks are clean; allocating a dedicated range (e.g. `0x1000 + test_id`) is safe.
4.  **Takeover window:** Acceptable. Re-deriving the overlay state takes only a few seconds (one fast probe cycle), whereas clustering overlay state adds significant sync complexity.
5.  **Debounce default:** 1s is fine. Recommend adding a minimum 2-3s inter-actuation lock to prevent FRR reload thrashing under rapid flaps, and documenting a non-zero recovery hold-down (e.g. 5s).
6.  **PR-1a/PR-1b split:** Correct. Keeps PR-1a focused on the prober/pin route stability.
7.  **PLAN-KILL tripwires:** Highly concrete and testable.

---

### 3. New v2-Introduced Defects & Weaknesses

#### Finding 1 (High): Ordering Hazard between Snapshot Push and FIB Generation Bump
*   **Severity:** High
*   **Reason:** If `BumpFIBGeneration()` is called before the snapshot push completes and is loaded by the userspace process, flows will invalidate and re-resolve against the *old* routes inside the helper. The subsequent snapshot push will not trigger another invalidation (since the generation is already updated), leaving the active traffic pinned to the dead interface.
*   **Concrete Fix:** Enforce a strict execution order: the routes-only actuator must wait for the snapshot push `apply_snapshot` ControlRequest to return success from the userspace process before calling `BumpFIBGeneration()`.

#### Finding 2 (Medium): Active Overlay Wipe on Operator Config Commit
*   **Severity:** Medium
*   **Reason:** [pkg/daemon/daemon_apply.go:740-776](file:///home/ps/git/bpfrx/pkg/daemon/daemon_apply.go#L740-L776) (`applyConfigLocked`) builds the FRR config purely from static `cfg`. If the prober had already transitioned to fail and injected an overlay route, a concurrent operator commit will call `applyConfigLocked`, which will wipe the active overlay, temporarily reverting routing to the dead link until the prober's next transition tick.
*   **Concrete Fix:** `applyConfigLocked` must retrieve the active overlay from `d.ipmon` (e.g., `d.ipmon.ActiveOverlay()`) and pass it to `assembleFRRConfig` and `buildRouteSnapshots` to preserve failover states across config changes.

#### Finding 3 (Low): Leak of Stale Probe Pin Rules on Daemon Crash
*   **Severity:** Low
*   **Reason:** If the daemon crashes or is killed, the netlink rule `fwmark <probe-mark> lookup <probe-table>` and the route in the dedicated table will leak in the kernel.
*   **Concrete Fix:** Upon startup, the RPM/routing manager must run a `clear()` pass on the dedicated probe-rule priority range (50-99) and flush the dedicated probe routing tables to prevent stale routing rules from leaking across restarts.

#### Finding 4 (Low): CPU Starvation on Continuous Prober Flapping
*   **Severity:** Low
*   **Reason:** Under rapid prober flapping, the 1s debounce timer will continually schedule the routes-only actuator, resulting in consecutive heavy `frr-reload` calls that block `applySem` and CPU.
*   **Concrete Fix:** Enforce a minimum inter-actuation throttle (e.g., 3 seconds) on the routes-only actuator to guarantee a CPU cooling window between FRR reloads.
