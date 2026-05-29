I will view the rest of the `trigger_kernel_arp_probe` implementation in `neighbor.rs` to see how it finishes the ICMPv6 setup and sends the packet.
# Adversarial Plan Review: Cold-Resolve Latency (#1651)

**Role Profile:** Senior Expert in HPC Networking, AF_XDP Zero-Copy Datapaths, Linux Netlink Routing Protocols, VLAN sub-interface demux, and High-Availability Chassis-Cluster Dataplane Design.
**Verdict:** **PLAN-NEEDS-REVISION**

---

## Executive Summary & Verdict

The plan's conclusion that live-target cold connect is fast (1–9 ms) on the smoke cluster is supported by the Gate-M' measurements, and the verification of scope-link warmup immunity is solid. 

However, **the recommendation to pursue Path C (Do-Nothing) as the primary option and conditionally KILL Path A is rejected.** The plan contains a critical security capability blind-spot that will cause silent, 100% packet loss for all cold-resolve connections in capability-constrained production environments. Furthermore, Path C exposes the firewall to a trivial Denial of Service (DoS) where a storm of connections to dead hosts blocks all legitimate new connections.

---

## Detailed Findings

### Finding 1: Lack of `CAP_NET_RAW` Causes Silent, Complete Failure of the Probe Pathway
*   **Severity:** **CRITICAL (Showstopper)**
*   **Description:**
    The cold-resolve mechanism relies entirely on `trigger_kernel_arp_probe` to trigger kernel neighbor resolution by opening raw sockets to transmit ICMP/ICMPv6 echo requests to the next hop.
    Under Linux, creating a raw socket (`SOCK_RAW`) requires the `CAP_NET_RAW` capability.
    If the userspace dataplane daemon is deployed in a secure, hardened containerized environment (e.g., Kubernetes Pods or systemd services with dropped capabilities), these socket creation calls will fail with `EACCES`/`EPERM`.
    The code handles a socket failure by silently returning:
    - Line 43–44: `if fd < 0 { return; }`
    - Line 76–77: `if fd < 0 { return; }`
    
    As a result, no probe is sent, the kernel never triggers ARP/NDP, and the connection remains unresolved until it hits the timeout (800ms or 2s) and the frame is dropped. In these environments, **100% of new connections will be permanently blocked.**
    
    This completely invalidates the plan's recommendation to "conditional-KILL" Path A. Path A (active dataplane synthesis on the XSK-TX ring) does not require raw socket syscalls at runtime once the AF_XDP socket is bound by the privileged coordinator. This makes Path A the only viable solution for capability-constrained environments.
*   **Quoted Evidence:**
    `userspace-dp/src/afxdp/neighbor.rs` lines 42–45:
    ```rust
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
                if fd < 0 {
                    return;
                }
    ```
    And lines 75–78:
    ```rust
                let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) };
                if fd < 0 {
                    return;
                }
    ```

---

### Finding 2: Dead-Host Connection Storm Denials of Service (DoS) to Live Cold Connections
*   **Severity:** **HIGH**
*   **Description:**
    When a destination host is unreachable or dead (no ARP/NDP reply), the SYN frame is held in the `pending_neigh` queue for the duration of the timeout (`PENDING_NEIGH_TIMEOUT_FAST_NS = 800_000_000` ns).
    The queue has a capacity of `MAX_PENDING_NEIGH = 4096`. When this queue is full, new cold-resolve connection packets are immediately dropped without being buffered, and no probe is sent.
    
    During server failovers, network splits, or simple port scans targeting dead or momentarily down IPs, the queue will rapidly fill. It takes only a moderate rate of dead-host SYNs (e.g., >5,120 SYNs/sec) to keep the queue permanently saturated.
    
    Once the queue is full, any connection attempt to a **live** cold host is immediately dropped (via `recycle_now = true` in the fallback). This completely blocks new connections to healthy targets, creating a severe operational hazard.
    
    This makes Path C (Do-Nothing) highly dangerous and operator-refutable. **Path B3 (negative cache / fast-fail) is therefore MANDATORY**, not an optional "operator choice."
*   **Quoted Evidence:**
    `userspace-dp/src/afxdp/poll_descriptor/mod.rs` lines 2644–2662:
    ```rust
                                    if binding.pending_neigh.len() < MAX_PENDING_NEIGH {
                                        let pending_flow_key = flow
                                            .as_ref()
                                            .map(|flow| flow.forward_key.clone())
                                            .or_else(|| {
                                                parse_session_flow_from_meta(meta)
                                                    .map(|flow| flow.forward_key)
                                            });
                                        binding.pending_neigh.push_back(PendingNeighPacket {
                                            addr: desc.addr,
                                            desc,
                                            meta,
                                            decision: pending_decision,
                                            flow_key: pending_flow_key,
                                            queued_ns: now_ns,
                                            probe_attempts: 0,
                                        });
                                        recycle_now = false;
                                    }
    ```

---

### Finding 3: Incomplete/Leaky Neighbor Removal on `update_neighbors` Replaces
*   **Severity:** **MEDIUM**
*   **Description:**
    When Go publishes an updated neighbor list via the `update_neighbors` command, Rust's `apply_manager_neighbors` is invoked with `replace = true`.
    To clear the previous set of neighbors, it retrieves `old_manager_keys` from `self.neighbors.manager_keys` and removes them from the sharded dynamic neighbor map (`self.neighbors.dynamic`) and the forwarding map (`self.forwarding.neighbors`).
    
    However, if a neighbor was dynamically learned by the Rust dataplane's `neigh_monitor_thread` upon receiving `RTM_NEWNEIGH`, it was inserted directly into `self.neighbors.dynamic`. It is **never** added to `self.neighbors.manager_keys`.
    
    If the dynamic neighbor is subsequently deleted in the kernel, and the Go control plane detects this and sends an `update_neighbors` replacement request, `apply_manager_neighbors` will **fail** to remove this neighbor from `self.neighbors.dynamic` because it was not in `old_manager_keys`.
    
    While the netlink monitor thread itself is designed to delete entries upon receiving `RTM_DELNEIGH`, any packet drop or socket buffer overflow in the netlink receive queue will cause a permanent cache leak of the dynamic neighbor in the dataplane cache. The Go control-plane's "safety reconciliation tick" is unable to clean up these leaked dynamic entries because they are ignored during `replace` since they are missing from `old_manager_keys`.
*   **Quoted Evidence:**
    `userspace-dp/src/afxdp/coordinator/mod.rs` lines 148–178:
    ```rust
            let old_manager_keys = if replace {
                self.neighbors
                    .manager_keys
                    .lock()
                    .map(|manager_keys| manager_keys.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            ...
            self.neighbors.dynamic.with_all_shards(|bulk| {
                if replace {
                    for key in &old_manager_keys {
                        bulk.remove(key);
                    }
                }
                for (ifindex, ip, entry) in neighbors {
                    bulk.insert((*ifindex, *ip), *entry);
                }
            });
    ```

---

### Finding 4: Absence of `SO_RCVBUF` Tuning on Rust Netlink Socket Risks Event Loss Under Flush Bursts
*   **Severity:** **LOW / MEDIUM**
*   **Description:**
    Unlike the Go listener (`pkg/daemon/daemon_neighbor_listener.go:132`), which explicitly sets a 1 MB receive buffer size (`ReceiveBufferSize: 1 << 20`), the Rust thread does not tune the socket's receive buffer size (`SO_RCVBUF`) at all.
    
    When a bulk neighbor flush like `ip neigh flush all` is executed on a system with a large number of neighbors, the kernel floods the netlink socket with a massive burst of `RTM_DELNEIGH` multicast messages.
    
    Due to the small default kernel netlink receive buffer size and the lack of tuning in Rust, the socket is highly vulnerable to buffer overflow and packet loss. If an event is dropped, the Rust dataplane will retain a stale neighbor entry in `dynamic_neighbors`, leading to blackholing or incorrect packet forwarding. The Go control-plane safety-net is unable to heal this because of the `old_manager_keys` filtering described in Finding 3.
*   **Quoted Evidence:**
    `userspace-dp/src/afxdp/neighbor.rs` lines 505–513:
    ```rust
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    ```

---

## Verification of Plan Assumptions

### Attack Vector 2: Scope-Link Routes Exclude On-Link Host Warmup
*   **Verification Status:** **CONFIRMED IMMUNE (Plan Assumption is Correct)**
*   **Description:**
    The plan's assertion that arbitrary on-link host IPs are warmer-immune is correct.
    `queue_warm_pass` in `userspace-dp/src/afxdp/coordinator/mod.rs` only iterates over `snapshot.routes_v4` and `snapshot.routes_v6`, and attempts to enqueue warming requests for `route.next_hop`.
    For a scope-link route (directly connected `/24` subnet), the route's `next_hop` is `None`.
    As verified in the code:
    - Line 718: `if let Some(hop) = route.next_hop`
    - Line 728: `if let Some(hop) = route.next_hop`
    This evaluates to `false` for scope-link routes, and `enqueue()` is never called.
    Thus, arbitrary host IPs on the local segment are completely excluded from warming, confirming that the on-link host tests were genuinely cold connects.
*   **Quoted Evidence:**
    `userspace-dp/src/afxdp/coordinator/mod.rs` lines 713–730:
    ```rust
            for routes in snapshot.routes_v4.values() {
                for route in routes {
                    if route.tunnel_endpoint_id != 0 {
                        continue;
                    }
                    if let Some(hop) = route.next_hop {
                        enqueue(route.ifindex, IpAddr::V4(hop));
                    }
                }
            }
            for routes in snapshot.routes_v6.values() {
                for route in routes {
                    if route.tunnel_endpoint_id != 0 {
                        continue;
                    }
                    if let Some(hop) = route.next_hop {
                        enqueue(route.ifindex, IpAddr::V6(hop));
                    }
                }
            }
    ```

---

## Conclusion & Necessary Revisions

Before the plan can be marked **PLAN-READY**, the following changes must be incorporated:

1.  **Re-evaluate Path A:** Path A should not be killed unconditionally/conditionally based only on the sub-ms RTT on the smoke cluster. It must be recognized as a critical architecture path for deployments that restrict runtime root capabilities (`CAP_NET_RAW`).
2.  **Elevate B3 to Mandatory:** Implement a basic fast-fail negative cache in the dataplane to prevent `pending_neigh` queue starvation during port scans or dead-host connection storms.
3.  **Fix Rust Netlink Socket Buffer:** Tune the Rust netlink socket receive buffer size (`SO_RCVBUF`) to 1 MB in `neigh_monitor_thread` to prevent dropped `RTM_DELNEIGH` events under flush bursts.
4.  **Fix Dynamic Neighbor Deletions in Replaces:** Modify `apply_manager_neighbors` to completely clear or correctly remove dynamically learned entries from `self.neighbors.dynamic` when processing a replacement (`replace == true`), rather than relying only on `old_manager_keys`.
