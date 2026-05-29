### Executive Summary & Verdict

**Verdict: PLAN-READY**

Following a thorough read-only pressure-testing of the design assumptions, race conditions, and network physics against the code in the worktree, the adjudication of the plan is correct. 

The empirical core of the plan holds: **Path C (do-nothing on the dataplane resolve mechanism)** is correct for steady-state latency because live cold connects resolve in **1–9 ms** on the supported cluster. However, **Path B3 (dead-host fast-fail / negative cache)** is elevated to a recommended shippable deliverable because of the very real availability risk posed by queue starvation.

Below is the expert analysis of each adjudication and the validation of the network physics surrounding the on-link host cells.

---

### 1. Verification of Adjudication (1): CAP_NET_RAW Downgrade

* **Verdict**: **Adjudication is correct and defensible. Downgrade accepted.**
* **Analysis**: Under Linux, opening a raw socket (`SOCK_RAW`) for `IPPROTO_ICMP` or `IPPROTO_ICMPV6` inside [userspace-dp/src/afxdp/neighbor.rs:42,75](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/neighbor.rs#L42-L75) requires the `CAP_NET_RAW` capability. In a cap-dropped containerized microservice, this syscall would fail with `EPERM` or `EACCES`, silently blocking all cold resolution.
* **Deployment Validation**: In the actual product architecture, `xpfd` is not a sandboxed application. As defined in [test/incus/xpfd.service](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/test/incus/xpfd.service#L8), `xpfd` is spawned as a **system-level root daemon**. It performs operations that inherently mandate maximum privilege (`CAP_NET_ADMIN` and `CAP_NET_RAW`):
  1. Attaches XDP/eBPF programs directly to physical interfaces.
  2. Binds and controls AF_XDP (XSK) sockets.
  3. Spawns an AF_PACKET raw socket receiver for VRRP cluster heartbeats.
  4. Reads and writes routes via AF_NETLINK sockets.
* **Conclusion**: Because there is no shipped deployment path where `xpfd` runs in a cap-dropped environment, a silent failure of `SOCK_RAW` will not occur in production. The downgrade of this issue from a Path-C blocker to a documented assumption is correct. However, keeping it as a Path-A "robustness pro" is correct because active XSK-TX synthesis bypasses `SOCK_RAW` completely, which would be a requirement if the deployment model ever shifts toward unprivileged container runtimes.

---

### 2. Verification of Adjudication (2): Dead-Host SYN-Storm Queue Starvation

* **Verdict**: **Adjudication is correct. Elevation of B3 is highly necessary.**
* **Analysis**: The `pending_neigh` queue is strictly capped at `MAX_PENDING_NEIGH = 4096` ([userspace-dp/src/afxdp/mod.rs:342](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/mod.rs#L342)). If a dead host (or a down subnet) is targeted by a stream of TCP SYNs, these packets are held in `pending_neigh` for up to `PENDING_NEIGH_TIMEOUT_FAST_NS = 800_000_000` ns (800 ms) before being dropped and recycled ([userspace-dp/src/afxdp/neighbor_dispatch.rs:110](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/neighbor_dispatch.rs#L110)).
* **The Starvation Hazard**: During a SYN storm targeting dead IPs (e.g., a subnet scan, a route-leak failover, or peer down-time), a rate of just ~5,120 SYNs/sec will saturate the 4096-capacity queue. At this point, the queue-full gate at [userspace-dp/src/afxdp/poll_descriptor/mod.rs:2644](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2644) triggers:
  ```rust
  if binding.pending_neigh.len() < MAX_PENDING_NEIGH { ... }
  ```
  Any new SYN packet for a **live, reachable cold host** will bypass the buffering logic and be dropped. Even though a probe is sent, when the RTM_NEWNEIGH event completes, the original SYN has been discarded and cannot be re-driven, forcing the client to wait for a full TCP RTO (typically 1 second). This represents a severe availability hazard.
* **The SMR Caveat Validation (Short-TTL + Invalidation)**: Naive negative caching can introduce a **probe suppression deadlock**. If we negative-cache a dead next-hop:
  1. We fast-fail incoming packets without buffering them.
  2. We do *not* fire a kernel probe (`trigger_kernel_arp_probe`).
  3. Because no probe is fired, the kernel never triggers ARP/NDP, meaning a recovered host has no trigger to reply.
  4. The host remains un-resolved, and we never receive the `RTM_NEWNEIGH` multicast event to clear the cache.
* **Mitigation**: To avoid this deadlock, the B3 implementation must adhere to these two constraints:
  - **Short TTL (1–2 seconds)**: Guarantees that probe suppression is transient, allowing the firewall to quickly attempt a new probe after a brief pause, protecting the queue without permanently blackholing recovered hosts.
  - **`RTM_NEWNEIGH` Invalidation**: If the host comes back and initiates traffic itself or broadcasts a Gratuitous ARP/Unsolicited NA, the kernel will resolve the neighbor, and the Rust monitor thread will receive `RTM_NEWNEIGH` ([userspace-dp/src/afxdp/neighbor.rs:297](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/neighbor.rs#L297)). Evicting the entry from the negative cache upon receiving this event ensures instantaneous path recovery.

---

### 3. Verification of Adjudication (3): Spun-off Cache-Correctness Issues

* **Verdict**: **Adjudication is correct. These are real bugs but belong in a separate ticket.**
* **The Dynamic-Neighbor Leak**: When Go publishes an updated neighbor list via `update_neighbors`, Rust executes `apply_manager_neighbors(replace=true)` ([userspace-dp/src/afxdp/coordinator/mod.rs:143](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/coordinator/mod.rs#L143)). The replacement logic only removes keys registered in `old_manager_keys` ([mod.rs:171](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/coordinator/mod.rs#L171)), which represents static or Go-seeded entries. Entries learned dynamically via the netlink thread are stored directly in `self.neighbors.dynamic` and are never added to `manager_keys`. Thus, a dynamic entry can never be pruned by a Go-side replacement.
* **The `SO_RCVBUF` Overflow Risk**: Rust's netlink monitor socket is opened and configured in [userspace-dp/src/afxdp/neighbor.rs:505-513](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/neighbor.rs#L505-L513) without configuring the receive buffer size (`SO_RCVBUF`). Unlike the Go-side monitor which uses a 1 MiB buffer, the Rust monitor relies on the small OS default. During a major network convergence event or bulk flush, this buffer will overflow, causing the socket to drop `RTM_DELNEIGH` multicast events. Because these deletions are lost, and because `apply_manager_neighbors` cannot evict dynamic keys, the stale entries leak permanently in the shared map, creating a routing/blackhole risk.
* **Conclusion**: These are critical cache-correctness bugs, but they do not influence cold-resolve latency (Gate-M' is immune to these leaks during latency checks). Conflating them into #1651 would result in unnecessary scope creep. Separating them into a dedicated cache correctness issue is the correct engineering decision.

---

### 4. Warmer-Immunity of On-Link Host Cells

The validity of the empirical measurements depends entirely on the fact that the on-link host cells were truly cold and unaffected by the proactive neighbor warmer. We can confirm this immunity via the codebase:

1. **Route Anatomy**: In the routing table, routes representing connected subnets (on-link routes) do not have a gateway IP address. The Go-side control plane pushes these routes to Rust with `next_hop = None`.
2. **Warmer Mechanics**: The proactive neighbor warmer loop is fed via `queue_warm_pass` ([userspace-dp/src/afxdp/coordinator/mod.rs:585](file:///home/ps/git/bpfrx/.claude/worktrees/1651-research-cold-resolve/userspace-dp/src/afxdp/coordinator/mod.rs#L585)). This function iterates over `snapshot.routes_v4` and `snapshot.routes_v6` and resolves next-hops to warm:
   ```rust
   if let Some(hop) = route.next_hop {
       enqueue(route.ifindex, IpAddr::V4(hop));
   }
   ```
   Because connected routes have `next_hop = None`, **no on-link host IP addresses are ever enqueued for warming.**
3. **Forwarding Resolution**: When a packet is sent to an on-link target (e.g., `172.16.80.200`), the forwarding engine matches the connected route, notices it has no gateway, and uses the destination IP itself as the next-hop to lookup the neighbor MAC ([userspace-dp/src/afxdp/forwarding/mod.rs]). 

Since these destination IPs are never pre-warmed, the on-link cell trials were guaranteed to exercise a 100% cold dataplane resolve path (as verified by the `GATEM1651 QUEUE` counter logs). The on-link cells carrying the overall latency conclusion is structurally sound.

### Final Verification and Recommendation

The plan is **PLAN-READY**. 

To ensure the B3 negative cache does not introduce connectivity blackholes for recovering hosts, the engineer should be explicitly instructed to implement a **short negative-cache TTL (e.g., 1–2 seconds)** and configure it to be **invalidated on receiving any `RTM_NEWNEIGH`** event for that next-hop.
