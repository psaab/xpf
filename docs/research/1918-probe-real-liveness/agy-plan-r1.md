# AGY Adversarial Review: Tunnel Keepalive Real-Liveness Plan

**Verdict**: `PLAN-NEEDS-WORK`

---

## Findings & Architectural Violations

### 1. The Datagram-ICMP ID-Rewrite Invalidation (Fatal Logic Mismatch)
* **Target Claim**: [§5a / §7.5 / §10.R3](file:///home/ps/git/bpfrx/.claude/worktrees/1918-research-probe-real-liveness/docs/research/1918-probe-real-liveness/plan.md#L96-L101)
* **Quoted Lines**:
  > *Line 97-98:* `the tunnel prober MUST set a unique Seq per probe and a stable per-prober ID, and require echo.ID == want.ID && echo.Seq == want.Seq on the reply`
  > *Line 194-195:* `Per-prober monotonic Seq (atomic) + stable ID (e.g. derived from tunnel name hash, low 16 bits) so replies bind to the probe.`
  > *Line 248-250:* `The kernel substitutes the on-wire ID with the socket's ephemeral port for udp4/udp6 ping sockets; x/net/icmp returns that substituted ID on read.`

* **Analysis**:
  There is a direct contradiction in the plan's proposed matching logic. On Linux, unprivileged ping sockets (`SOCK_DGRAM`, `IPPROTO_ICMP`) automatically overwrite the `ID` field in the ICMP header with the socket's local source port (ephemeral port) during transmission. 
  1. If `want.ID` is set to the custom tunnel-name hash (e.g., `hash(tunnel_name)`), the verification `echo.ID == want.ID` will **always fail**, because the kernel will override the ID on the wire, the peer will return that port, and `x/net/icmp` will parse it as the socket port. All probes will be falsely flagged as `ProbeDead`.
  2. If multiple tunnels share a single `icmpConn` socket (as referenced on Line 83: *"concurrent tunnel probers on a shared socket"*), they will all share the exact same source port. Therefore, the kernel-substituted ID (the port) will be identical for all concurrent probes. The ID *cannot* demux replies between tunnels.
* **Mitigation**: The plan must drop the custom `ID` comparison entirely. Demuxing on a shared socket (or even identifying late replies on the same port) must rely exclusively on a unique **Sequence number (`Seq`)** and/or a randomized **nonce inside the `Data` payload**, which are preserved by the kernel.

---

### 2. The VRF `SO_BINDTODEVICE` Overlay vs. Underlay Routing Mismatch
* **Target Claim**: [§5b / §10.R2](file:///home/ps/git/bpfrx/.claude/worktrees/1918-research-probe-real-liveness/docs/research/1918-probe-real-liveness/plan.md#L102-L108)
* **Quoted Lines**:
  > *Line 104-106:* `The prober must be able to bind the probe socket to the tunnel's VRF device (SO_BINDTODEVICE to vrf-<instance>), analogous to pkg/rpm's vrfDialer.`

* **Analysis**:
  This design overlooks the routing divergence between the tunnel's overlay and underlay.
  1. The keepalive loop pings the tunnel's outer `tc.Destination` (the remote endpoint underlay IP), **not** the inner overlay IP.
  2. A tunnel interface is bound to a VRF (`tc.RoutingInstance`) to route its *inner* (overlay) traffic. However, the outer tunnel encapsulated traffic is resolved in the underlay routing domain (typically the default/global routing table).
  3. If we call `SO_BINDTODEVICE` to bind the probe socket to `vrf-<instance>` (the overlay VRF), the kernel will look up the underlay `tc.Destination` IP inside the overlay VRF's routing table. In typical deployments, the overlay VRF does *not* contain routes to the underlay peer IP. The probe will fail with `ENETUNREACH` or `EHOSTUNREACH`, resulting in false down-transitions or permanent `ProbeUnsupported` states.
  *Note*: `pkg/rpm`'s binding is correct because RPM probes verify services/IPs *inside* the VRF routing instance. A tunnel keepalive checking the outer endpoint is checking the underlay.
* **Mitigation**: If we must bind the socket, it should bind to the specific underlay interface or underlay VRF, not the overlay VRF. Alternatively, the keepalive probe should target the tunnel peer's inner IP (which isn't currently present in `TunnelConfig`). If we check underlay reachability, the probe must bypass the overlay VRF.

---

### 3. `SO_BINDTODEVICE` Privilege Catch-22 with Unprivileged Ping Sockets
* **Target Claim**: [§6.Axis A (Option A1) vs §10.R2](file:///home/ps/git/bpfrx/.claude/worktrees/1918-research-probe-real-liveness/docs/research/1918-probe-real-liveness/plan.md#L116-L118)
* **Quoted Lines**:
  > *Line 116-118:* `Option A1 — datagram ICMP (udp4/udp6) via x/net/icmp [RECOMMENDED]. ... No CAP_NET_RAW when ping_group_range admits the gid. ... Does NOT require root.`
  > *Line 245-247:* `open the socket per-probe (cheap) so a late-created VRF is picked up; tolerate bind failure as Unsupported rather than crashing.`

* **Analysis**:
  On Linux, `SO_BINDTODEVICE` requires `CAP_NET_RAW` or `CAP_NET_ADMIN` privileges. Prior to Linux 5.7, this was an absolute rule. Since Linux 5.7, unprivileged users can use `SO_BINDTODEVICE` **only if the socket is not already bound**.
  However, [`icmp.ListenPacket(network, listenAddr)`](file:///home/ps/git/bpfrx/.claude/worktrees/1918-research-probe-real-liveness/pkg/cluster/monitor.go#L417) creates *and* immediately binds the underlying UDP socket. 
  When the unprivileged daemon calls `SO_BINDTODEVICE` after `icmp.ListenPacket`, it will fail with `EPERM` or `EACCES` on all kernel versions. 
  This breaks Option A1's unprivileged design for all VRF-bound tunnels: they will consistently fail the bind, return `ProbeUnsupported`, and default to the C1 policy, rendering the keepalive feature entirely useless for VRF-bound tunnels under unprivileged execution.
* **Mitigation**: To achieve unprivileged VRF binding, the socket creation must be performed manually via `syscall` to configure `SO_BINDTODEVICE` *before* calling `bind`. `golang.org/x/net/icmp` does not natively support this ordering out-of-the-box, meaning a custom socket initialization flow is required.

---

### 4. Fail-Open Policy for `ProbeUnsupported` Hides Outages
* **Target Claim**: [§6.Axis C (Option C1)](file:///home/ps/git/bpfrx/.claude/worktrees/1918-research-probe-real-liveness/docs/research/1918-probe-real-liveness/plan.md#L139-L146)
* **Quoted Lines**:
  > *Line 139-141:* `Option C1 — fail-safe-on-unknown but DO NOT count as failure / DO NOT flap [RECOMMENDED]. On ProbeUnsupported: do not increment Failures, do not call LinkSetDown, do not call LinkSetUp; hold the prior Up value`

* **Analysis**:
  Holding the link `UP` on `ProbeUnsupported` introduces an operational risk of silent blackholes.
  If the daemon encounters resource limits (e.g. running out of file descriptors / `EMFILE` during `ListenPacket`) or capability issues (like the `SO_BINDTODEVICE` privilege failure described above), the prober becomes `Unsupported`. 
  Under C1, the keepalive loop holds the link `UP` indefinitely. If the peer dies during this time, the outage goes completely undetected, defeating the purpose of configuring keepalives.
  This diverges from the precedent in [`pkg/cluster/monitor.go:371-374`](file:///home/ps/git/bpfrx/.claude/worktrees/1918-research-probe-real-liveness/pkg/cluster/monitor.go#L371-L374), where socket creation/dial errors directly return `false` (fail-closed/unreachable).
* **Mitigation**: Do not hide transport/permission failures under a global "hold UP" policy. A transport error should either fail-closed (like `monitor.go`) or allow the operator to configure the fallback via Axis C Option C3.

---

### 5. Verification of Lock-Scope Fix (Axis D) and Existing Code Representation
* **Analysis**:
  1. **Fact Check of Existing Code**: The plan's descriptions of [`keepaliveLoop`](file:///home/ps/git/bpfrx/.claude/worktrees/1918-research-probe-real-liveness/pkg/routing/tunnel.go#L980-L1021) and [`probeICMP`](file:///home/ps/git/bpfrx/.claude/worktrees/1918-research-probe-real-liveness/pkg/routing/tunnel.go#L1025-L1051) are correct. The lock-scope defect is real; `state.mu` is held across netlink calls in the current codebase, creating a latency hazard for status readers.
  2. **TOCTOU in Axis D**: Releasing `state.mu` before the netlink call is safe. Since `state.Up` is only mutated inside the `keepaliveLoop` goroutine, there is no concurrent writer that can invalidate the transition logic. `Apply` safely checks `runner.state.Up` under the lock to coordinate its config reconciliation. Redundant netlink calls to `LinkSetUp` on an already-up interface are safe kernel no-ops.

---

## Summary of Completed Work
* Performed a detailed, read-only analysis of the worktree plan at `plan.md` and related source files in `pkg/routing/tunnel.go`, `pkg/cluster/monitor.go`, and `pkg/rpm/rpm.go`.
* Identified a logic bug in ID matching due to Linux kernel `SOCK_DGRAM` ID rewrites.
* Identified an overlay/underlay routing mismatch for VRF-bound tunnels.
* Identified a privilege catch-22 for unprivileged VRF socket binding.
* Critiqued the fail-open fallback policy and confirmed the safety of the lock-scope fix.
