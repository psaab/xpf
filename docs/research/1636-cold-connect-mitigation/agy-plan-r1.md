# AGY adversarial plan review — round 1 (#1636)

**Job ID**: adversarial-review-mpprwcvt-6ptuq6
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` @ `ee82b880b`

## VERDICT: PLAN-NEEDS-MAJOR

## Findings (verbatim from AGY)

### Finding 1 [SEVERITY: high] Spawning Threads on refresh_runtime_snapshot Invites Control-Plane Crash under Config Storms

- File/Line: `userspace-dp/src/afxdp/coordinator/mod.rs:435` (refresh_runtime_snapshot tail)
- Description: The plan asserts that spawning a thread per snapshot to warm neighbors is "non-blocking" and that "dedup will absorb this." This is a major operational vulnerability. Under config storms (e.g., 10 snapshots/sec) and standard routing tables (e.g., 100 next-hops), if some next-hops are permanently unreachable/offline (e.g., a dead gateway or dynamic DNS peer that went down), they will never resolve and will never enter `forwarding.neighbors` or `dynamic_neighbors`. The `already_resolved` check will fail for them every single time. Consequently, the single-threaded coordinator will spawn 10 threads/sec and attempt 1,000 concurrent `socket(SOCK_RAW)` syscalls per second. This bursty allocation of raw sockets under load will exhaust the process's file descriptor limits (hitting the per-process FD cap) and system thread limits, crashing the control plane.
- Mitigation: Introduce a lightweight rate-limiting cache (e.g., a `last_probed_at: FastMap<(i32, IpAddr), u64>` map) inside `NeighborManager` to ensure that no specific `(ifindex, hop)` combination is probed more than once per 5 seconds, regardless of snapshot churn or unreachable targets.

### Finding 2 [SEVERITY: high] Rejection of Option D is Based on Mathematically and Logically Flawed RTO Deduplication Logic

- File/Line: `userspace-dp/src/afxdp/neighbor_dispatch.rs:100-103` (and plan doc §6.4)
- Description: The plan's justification for rejecting Option D is incorrect. The plan claims: *"The client retransmit at ~1 s would arrive against a still-pending neighbor and we'd drop that too."* This is false. Each packet queued in `pending_neigh` carries its own individual timestamp `queued_ns` (written at arrival in `poll_descriptor/mod.rs:2658`), and the timeout check in `neighbor_dispatch.rs:100` uses `now_ns.saturating_sub(pkt.queued_ns) > PENDING_NEIGH_TIMEOUT_NS` per packet.
- Derivation: If `PENDING_NEIGH_TIMEOUT_NS` is lowered to 800ms:
  1. t=0 ms: SYN #1 arrives, queued.
  2. t=800 ms: SYN #1 is dropped (queue becomes empty).
  3. t=1000 ms: Client sends first RTO retransmit (SYN #2). Since the queue is empty, `already_probing` is false, SYN #2 is queued, and a fresh ICMP probe is fired.
  4. SYN #2 gets a fresh 800ms window (expiring at t=1800ms).
  5. t=1020 ms: Kernel ARP resolves, netlink notifies, and SYN #2 is successfully forwarded.
  - Lowering `PENDING_NEIGH_TIMEOUT_NS` to 800ms ensures the connection succeeds at **~1020 ms** instead of **3371 ms** (a savings of 2.3 seconds), without causing a second drop or waiting for the 3000ms client RTO #2. Rejection of Option D must be reversed.

### Finding 3 [SEVERITY: medium] Redundant and Broken Underlay Tunnel Endpoint Warming

- File/Line: Plan doc §6.1, `docs/userspace-icmp-te-debugging.md:112`
- Description: The plan recommends warming `forwarding.tunnel_endpoints.values().map(|t| t.destination)`. This is dual-defective:
  1. For GRE/IPSec tunnels, userspace does not perform forwarding or L2 encapsulation; it overrides the disposition to `MissingNeighbor` and routes them to the kernel slow path. The kernel handles encapsulation and underlay neighbor resolution natively.
  2. If the tunnel destination is multi-hop away, it does not have a local ARP/neighbor entry. The only meaningful neighbor is the next-hop gateway (which is already covered by `routes_v4/v6` warming). Attempting to send raw ICMP probes to a remote multi-hop IP via `SO_BINDTODEVICE` is useless and risks generating broken broadcast ARPs for a non-local destination.
- Mitigation: Remove `tunnel_endpoints` from the warming set. Focus exclusively on `routes_v4/v6` next-hops and `fabrics` peer IPs.

### Finding 4 [SEVERITY: medium] Option B-Only is a Gate-Failure Trap (Proves Option C is Mandatory)

- Description: A hostile review of Point 8 ("Is B-only sufficient?") reveals a gate-failure trap. In zero-copy AF_XDP mode, the network driver's TX queues are fully owned by XSK, making kernel-initiated TX (such as standard raw ICMP probes or ARP requests) highly prone to driver-level packet drops or queue conflicts. If B alone (kernel retrans=250ms) is shipped, the first connection to a cold next-hop will trigger a probe that is likely lost, forcing a 250-300ms resolution wait. This will **FAIL** the ≤200ms connection acceptance gate on the very first connection. Proactive warming (Option C) is therefore mathematically mandatory because it pushes this resolution latency into the background (at config-apply), allowing the first connection to establish in **< 2ms**.

### Finding 5 [SEVERITY: low] Kernel Rate-Limit Claim is 100% Correct (Option A Demoted)

- File/Line: `userspace-dp/src/afxdp/neighbor_dispatch.rs:33-37`, `net/core/neighbour.c`
- Description: The plan's central claim in §5 is correct. A walk of the Linux kernel's `net/core/neighbour.c` shows that in `__neigh_event_send()`, if `neigh->nud_state & NUD_INCOMPLETE` is true, the kernel simply queues the `skb` in the `arp_queue` and returns `1` immediately. It does **not** call `neigh_probe()` or trigger a new ARP/NDP solicitation on the wire. A fresh solicitation is only sent when the kernel's neighbor timer (`neigh->timer`) expires, which is governed by `retrans_time_ms`. Therefore, extending userspace `PROBE_SCHEDULE_NS` (Option A) has zero marginal value for accelerating resolution and only serves as a heartbeat. Option B (sysctl tuning) is indeed the dominant control knob.

### Finding 6 [SEVERITY: low] HA Failover VRRP-GARP Interaction is Safe

- File/Line: `pkg/vrrp/instance.go:779`, `pkg/vrrp/instance.go:1070`
- Description: The HA-failover risk flagged as medium in §9 and §12.6 is a non-issue. On RG-promote, `becomeMaster()` sends GARP bursts using the virtual IPs (VIPs) as the sender IP and the physical interface MAC as the sender MAC. Simultaneously, Option C's warm pass sends unicast ICMP echo probes to peer next-hops, which default to using the primary physical IP as the source IP and the physical MAC as the source MAC. Both sets of traffic originate from the exact same physical port and map to the exact same physical MAC. Thus, there is **zero switch FIB or MAC table confusion** upstream. Both paths are consistent.

### Finding 7 [SEVERITY: low] Lack of Automated CI Latency Bounds Testing

- File/Line: Plan doc §10
- Description: The proposed unit tests in `coordinator/tests.rs` only verify that the warm pass fires sockets. The ≤200ms connection gate is tested only observationally/manually on the physical "loss userspace cluster." This invites silent latency regressions in CI.
- Mitigation: Implement a synthetic unit/integration test in `userspace-dp/src/afxdp/neighbor_dispatch.rs` that mocks Netlink events and verifies that the `pending_neigh` retry queue flushes successfully within a simulated time window.

## Recommendation

Ship **B + C + D** with the following modifications:

1. **Implement C (Proactive Warming)**: Warm only `routes_v4/v6` next-hops and `fabrics` peer IPs. **Do not warm `tunnel_endpoints`**.
2. **Harden Thread Spawning in C**: Add a lightweight rate-limiting map (`last_probed_at`) inside `NeighborManager` to prevent raw socket storming/FD exhaustion during config storms with unreachable gateways.
3. **Implement B (sysctl retrans_time_ms=250)**: Necessary to limit resolution time of dynamically learned/unknown next-hops when the initial raw probe is lost due to AF_XDP zero-copy TX queues.
4. **Implement D (Lower PENDING_NEIGH_TIMEOUT_NS to 800ms)**: Necessary to prevent client RTO #1 retransmits from stalling for 3 seconds. The packet-level timestamping logic ensures that lowering the timeout to 800ms safely routes TCP RTO retransmissions to immediate success on the first retransmit, cutting latency to ~1.02s in the worst-case packet loss scenario.
