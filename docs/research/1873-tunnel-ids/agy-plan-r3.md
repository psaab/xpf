# Adversarial Plan Review: Round 3 (Convergence Round)

We have analyzed the proposed v3 design against the codebase in the `/home/ps/git/bpfrx/.claude/worktrees/1873-research` worktree. Below is the adversarial pressure-testing of the plan section 11 open questions with concrete codebase evidence.

---

### 1. Conditional vs Blanket R-C Gate: Worked Trace of Plaintext Leak

The assumption in the plan that **resolvability** of the `tunnel_endpoint_id` in the Rust [ForwardingState](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/types/forwarding.rs#L14) is a correct proxy for the kernel possessing the tunnel netdev/routes is **incorrect**. 

We have identified a concrete, non-transient scenario where a packet is reinjected to the kernel slow path and leaks in plaintext:

1. **Admin-Down State**: A configured WireGuard tunnel `wg0.0` (or GRE tunnel `gr-0/0/0.0`) is set to admin down (e.g. via `ip link set wg0.0 down`).
2. **Kernel Route Flush**: When an interface goes down, the Linux kernel automatically deletes all associated routing table entries pointing to that interface.
3. **Stale Dataplane Snapshot**: Because `wg0.0` still exists as a device in the network namespace, [buildLinkSnapshot](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/dataplane/userspace/interfaces.go#L372) (via `net.InterfaceByName("wg0.0")`) returns a valid, non-zero `ifindex`. Additionally, the Go daemon's [monitorLinkState](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/daemon/daemon_flow.go#L407) only triggers SNMP notifications and does not invoke `d.dp.ApplyConfig()` to refresh the dataplane state. The Rust worker's [ForwardingState.tunnel_endpoints](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/types/forwarding.rs#L23) map therefore retains the endpoint ID and resolves it.
4. **Reinjection and Plaintext Leak**:
   * A packet matching the tunnel's session hits a slow-path door (e.g. `EncapError::NoSession` pre-handshake fallback).
   * The conditional gate in [maybe_reinject_slow_path_from_frame](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L129) permits the packet because its `tunnel_endpoint_id` resolves in [ForwardingState](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/types/forwarding.rs#L23).
   * The unencapsulated inner packet is written to the slow-path TUN `xpf-usp0`.
   * The kernel receives the packet, looks up the destination IP, finds that the route via `wg0.0` is missing, and falls back to the default route pointing to the physical WAN interface (e.g. `eth0`).
   * The packet is transmitted over the WAN in **plaintext**, violating the security boundaries.

---

### 2. R-E Admission Rerouting

**No tunnel mode is harmed** by skipping userspace outer-neighbor buffering for tunnel-marked packets.

* **GRE**: As verified in [encapsulate_native_gre_frame](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/gre.rs#L299), GRE interfaces are bound to their respective VRFs. When a GRE packet is reinjected, the kernel GRE driver encapsulates the packet inside the correct VRF domain. The kernel then triggers its own ARP/ND neighbor resolution for the outer destination IP.
* **WireGuard**: The [wg_control_loop](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L81) thread handles UDP socket delivery. When a packet is written to `wgN` and fails encap, `wg_control` drives the handshake. The kernel similarly executes standard ARP/ND resolution for the outer peer endpoint under its socket routing context.
* Userspace buffering via [retry_pending_neigh](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/neighbor_dispatch.rs#L85) is thus redundant for tunnels and can be safely bypassed.

---

### 3. Counter Visibility

There is **no objection** to extending the [ProcessStatus](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/protocol/control.rs#L60) structure. Both the Rust and Go sides serialize/deserialize via JSON Serde allowing default/optional fields. Adding `tunnel_encap_unresolved` and `retry_pending_neigh_tunnel_drops` will maintain backward and forward compatibility.

---

### 4. Purge-Walk Coverage

We **confirm** that `recent_session_deltas` and eventstream replay buffers do not require traversal during the R-D purge.

* [recent_session_deltas](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/mod.rs#L87) is a ring buffer used only for telemetry status retrieval.
* The eventstream replay buffer (e.g. in [userspace-dp/src/event_stream/codec.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/event_stream/codec.rs#L209)) holds pre-serialized byte arrays for replay during connection drops. Because the session-delete machinery will generate new `SessionClose`/`Delete` events, any replayed `SessionOpen` will be immediately superseded by its corresponding deletion.

---

### 5. Remaining Holes

The primary hole is the plaintext leak detailed in Question 1. An additional operational gap exists because the Go coordinator does not subscribe to netlink interface operational state changes to trigger config/snapshot rebuilds; thus, the Rust `ForwardingState` remains stale during interface flaps.

---

### Summary of Work
1. Evaluated `plan.md` in detail against the current codebase in `/home/ps/git/bpfrx/.claude/worktrees/1873-research`.
2. Explored and traced the interaction between the Go-side snapshot builder, SNMP link monitoring, the slow path reinjection interface (`xpf-usp0`), and kernel-side routing behavior.
3. Identified a critical vulnerability where admin-down tunnel interfaces cause unencapsulated packets to leak in plaintext under the proposed conditional R-C gate.
4. Ratified the designs for R-E, ProcessStatus telemetry, and R-D session purge scope.

---

VERDICT: PLAN-NEEDS-REVISION (1. Subscribe to netlink operational state changes to trigger dataplane snapshot refreshes when tunnel interfaces change state. 2. Modify Go snapshot building in `buildLinkSnapshot` and `buildTunnelEndpointSnapshots` to verify the interface state flags or exclude interfaces that are not operational so their IDs do not resolve in the Rust R-C gate.)
