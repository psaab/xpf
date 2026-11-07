# Userspace Dataplane: Cold Start & Neighbor Resolution

**Date:** 2026-03-22
**Commits:** `e0c01ac` through `2f818e8`

> **Accuracy note (#1645):** The "~2ms" cold-connect figures below
> describe the intended steady-state target, not the current measured
> cost. Cold TCP connect is **currently measured ~3.371s** under a cold
> neighbor cache (after `ip neigh flush all`), because of the gap
> between the 260 ms userspace probe schedule and the 2000 ms pending-
> neighbor timeout in `neighbor_dispatch.rs`. The mitigation is tracked
> by **#1636**; once it lands these figures will be updated to the
> post-fix measurement. Treat the "~2ms" values here as the design
> goal, not a shipped result.

## Problem Statement

After daemon restart or when encountering a new destination host, the
userspace AF_XDP dataplane could not establish new TCP connections.
The first SYN packet hit `MissingNeighbor` (no ARP/NDP entry for the
egress next-hop) and was either dropped or reinjected to the kernel
slow-path TUN, resulting in:

- **Infinite timeout** for new TCP connections (initial state)
- **~1.2s delay** after adding slow-path reinject (TCP SYN retransmit)
- **~2ms target** after all fixes (buffer-and-retry with ICMP probe)
  — but cold connect is **currently measured ~3.371s** under a cold
  neighbor cache; mitigation tracked by #1636 (see accuracy note above)

## Root Causes

### 1. Zero-Copy Fill Ring Bootstrap

**Problem:** After XSK socket bind in zero-copy mode, the mlx5 driver
runs NAPI during channel activation to post fill ring entries as
hardware WQEs. If the fill ring was empty at bind time,
`xsk_buff_alloc_batch()` failed and the driver never retried — leaving
the hardware RQ with zero WQEs forever.

**Fix:** Prime the fill ring BEFORE the `xsk_bind()` call, not after.
(`8a05d52`)

```
// Before: prime_fill_ring_offsets(&mut device, &offsets) called AFTER bind
// After:  prime_fill_ring_offsets(&mut device, &offsets) called BEFORE bind
```

**Verification:** `rx_xsk_buff_alloc_err` counter stopped incrementing
on daemon restart.

### 2. Heartbeat Gating Deadlock

**Problem:** The `xsk_rx_confirmed` flag gated heartbeat writes on
receiving at least one XSK packet. But without heartbeat, the XDP shim
did `XDP_PASS` (kernel forwarding), so no XSK packets ever arrived —
a deadlock. With the pre-bind fill ring prime fixing the underlying WQE
issue, the gate was unnecessary.

**Fix:** Remove `xsk_rx_confirmed` gating entirely. All queues write
heartbeat immediately after the grace period. (`161053a`)

### 3. XDP_PASS on Zero-Copy Breaks VLAN ARP Demux

**Problem:** On mlx5 in zero-copy mode, `XDP_PASS` for non-IP traffic
(ARP replies) doesn't properly deliver through VLAN demux. The ARP
reply arrives on the parent interface (`ge-0-0-2`), the XDP shim
returns `XDP_PASS`, but the zero-copy-to-SKB conversion path skips
the VLAN tag processing needed to steer the packet to `ge-0-0-2.80`.
The kernel sees the ARP reply but can't match it to the VLAN
sub-interface, leaving neighbor entries stuck in `INCOMPLETE` state.

This also affected `cpumap_or_pass` — cpumap redirect for ARP replies
doesn't trigger the kernel's L2 ARP state machine either.

**Impact:** The kernel could never resolve ARP/NDP for hosts on VLAN
sub-interfaces while the XDP shim was attached to the parent.

**Fix:** Use `XDP_PASS` for non-IP (not cpumap). While XDP_PASS has
the VLAN demux issue, the ICMP socket probe (below) bypasses it
entirely by using the kernel's own ARP/NDP stack. (`87a60a3`, `8211f35`)

### 4. AF_PACKET `send_raw_frame` Silently Drops on VLAN Sub-Interfaces

**Problem:** The helper sent ARP requests via `AF_PACKET SOCK_RAW` on
VLAN sub-interfaces (e.g., `ge-0-0-2.80`). The `send()` syscall
returned success (42 bytes sent) but the frame never reached the wire.
The kernel accepted the frame into the socket buffer but the VLAN
sub-interface egress path dropped it — likely due to TX VLAN offload
expecting the tag in descriptor metadata, not in the frame payload.

**Diagnosis:**
- `tcpdump -i ge-0-0-2.80` showed 0 ARP packets from the helper
- `tcpdump -i ge-0-0-2` (parent) also showed 0
- Python `socket.AF_PACKET` with `bind()` + `send()` worked (different
  kernel code path than `sendto()` with `sll_ifindex`)
- The `sll_protocol` field was set incorrectly: `(proto as i32).to_be()`
  byte-swaps all 4 bytes instead of just the lower 16 bits

**Multiple attempted fixes (all failed for VLAN):**
1. `sendto()` with `sll_ifindex` — frame silently dropped
2. `bind()` + `send()` — frame accepted but never transmitted
3. `bind()` + `sendto()` with explicit `sockaddr_ll` — same
4. Insert 802.1Q tag + send on parent interface — TX offload strips tag
5. Netlink `RTM_NEWNEIGH` with `NUD_INCOMPLETE` — kernel sends ARP but
   reply doesn't survive XDP_PASS VLAN demux

**Working fix:** ICMP socket probe (see below).

### 5. ICMP SOCK_DGRAM `sendto()` Silently Fails

**Problem:** The `trigger_kernel_arp_probe()` function used
`socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` to send an ICMP echo
request. The `socket()` call succeeded but `sendto()` returned
`EINVAL` silently (return value not checked). The code then closed
the socket without falling through to the `SOCK_RAW` fallback.

Same issue for IPv6: `socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)`.

**Fix:** Use `SOCK_RAW` directly for both IPv4 and IPv6. Set
`IPV6_CHECKSUM` sockopt for ICMPv6 auto-checksum. (`fd53f19`, `2f818e8`)

The original EINVAL was NOT inherent to DGRAM ping sockets — it came
from sending a **raw-style buffer (leading IP header)** through the
DGRAM socket: the kernel read the IPv4 version/IHL nibble `0x45` as the
ICMP type and rejected it via `ping_supported()`. The correct DGRAM
send is the ICMP message ONLY (no IP header), which is exactly the
shape the raw path already uses. See the `SOCK_DGRAM` fallback below.

```rust
// IPv4: SOCK_RAW IPPROTO_ICMP + SO_BINDTODEVICE
let fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name);
sendto(fd, icmp_echo, target_addr);

// IPv6: SOCK_RAW IPPROTO_ICMPV6 + SO_BINDTODEVICE + IPV6_CHECKSUM
let fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name);
setsockopt(fd, IPPROTO_ICMPV6, IPV6_CHECKSUM, &2); // offset 2
sendto(fd, icmpv6_echo, target_addr);
```

### 5b. SOCK_DGRAM Ping-Socket Fallback for Rootless / No-CAP_NET_RAW (#2482)

**Context:** `SOCK_RAW` requires CAP_NET_RAW. xpfd runs as root by
default (held for AF_XDP/BPF), so the raw path is always taken in
production. But under the rootless / unprivileged-container /
dropped-privilege substrate tracked by #1958, raw-socket creation
fails with EPERM/EACCES and `trigger_kernel_arp_probe()` previously
returned silently — neighbor discovery stalled, leading to forwarding
drops.

**Fix:** `select_probe_socket()` tries `SOCK_RAW` first; on creation
failure it falls back to an unprivileged **`SOCK_DGRAM` ICMP ping
socket** (`IPPROTO_ICMP` / `IPPROTO_ICMPV6`). The ping socket is
creatable without CAP_NET_RAW when the process GID is inside
`net.ipv4.ping_group_range` (operator-tunable; on a locked-down host
where the range is empty, the fallback is itself best-effort and the
probe is skipped as before).

DGRAM ping-socket send semantics (differ from raw — getting them wrong
was the original EINVAL):

- **Buffer is the ICMP message only**, never an IP header — same 8-byte
  Echo Request the raw path sends (`build_icmp4_echo` / `build_icmp6_echo`).
- **The kernel rewrites the ICMP Echo `id`** to the socket's bound port
  (the ping-socket contract) and **recomputes the checksum**, so the v4
  DGRAM buffer leaves both zero (byte-distinct from the raw buffer's
  precomputed `0xf7ff`). Do NOT rely on a self-chosen id.
- **`IPV6_CHECKSUM` is a RAW-only sockopt** — a DGRAM ping6 socket
  computes the checksum intrinsically, so the offset sockopt is set on
  the raw path only.
- **`SO_BINDTODEVICE` itself needs CAP_NET_RAW**, so on the DGRAM
  fallback it is typically a no-op (EPERM, ignored, best-effort). The
  destination route still selects the correct egress interface for a
  directly-connected next-hop, so resolution proceeds regardless.

The goal is only to drive the kernel to ARP/NDP-resolve the next-hop;
any egress to an unresolved neighbor triggers resolution, so the echo's
reply is irrelevant. The selection seam is unit-tested
(`probe_socket_tests` in `neighbor.rs`) without manipulating process
capabilities: a raw failure must produce a DGRAM attempt + selection.

### 5c. IPv6 NDP Solicit Omitted `sin6_scope_id` for Link-Local (#2969)

**Problem:** `trigger_kernel_arp_probe()` built the IPv6
`sockaddr_in6` from `mem::zeroed()` and set only `sin6_family` +
`sin6_addr`, leaving `sin6_scope_id == 0`. Linux **cannot route a
link-local (`fe80::/10`) datagram without the interface scope**, so for
a link-local next-hop the `sendto` failed (EINVAL/ENETUNREACH) and the
NDP solicit was never emitted. The `sendto` return was also ignored in
both the IPv4 and IPv6 branches, so the failure was completely silent:
probe counters advanced as if NDP was nudged but no packet left the box,
and the next-hop never resolved — an IPv6 forwarding blackhole to
link-local next-hops that cleared only when unrelated traffic happened to
trigger kernel resolution. `SO_BINDTODEVICE` does not substitute for the
scope id (and on the DGRAM fallback it is itself a no-op without
CAP_NET_RAW).

**Fix:** `trigger_kernel_arp_probe()` now takes the egress `ifindex`
(available at every call site — `item.ifindex` in the warmer/resolver,
`key.0` in dispatch, `neigh_if` in the cold-packet path) and threads it
into `sin6_scope_id` via the pure `build_solicit_sockaddr_in6()` helper.
The scope id is set unconditionally: link-local **requires** it, and a
global/ULA destination ignores it, so no link-local special-case is
needed. Both branches now check the `sendto` return and `eprintln!` a
failure (fires only on a probe send error — rare — so it does not
violate the per-tick logging rules) instead of swallowing it. The
sockaddr construction is unit-tested as a fail-on-revert in
`probe_socket_tests` (`ndp_solicit_sockaddr_carries_ifindex_scope_for_link_local`):
the test goes RED if `sin6_scope_id` reverts to 0.

Distinct from #2482 (DGRAM fallback when no CAP_NET_RAW),
#2452/#2494 (Go-side static-route/RPM link-local scoping), and the
#2918/#2919 neighbor-dump work.

### 6. Buffer Retry Not Running on Empty RX

**Problem:** The `retry_pending_neigh()` function only ran at the end
of `poll_binding()`, after RX packet processing. When no new packets
arrived (the common case during cold ARP — the SYN was buffered and
no other traffic), `poll_binding()` returned early at the
`available == 0` check without ever checking the pending buffer.

The buffered SYN sat idle until the TCP retransmit (~1s) generated a
new packet, waking the RX path. This caused the classic "1.2s TCP
black hole" — the ARP resolved in ~5ms but the retry didn't fire
for another ~1195ms.

**Fix:** Call `retry_pending_neigh()` on the `available == 0` early
return path, before `counters.flush()`. This runs the retry on every
1ms poll cycle (interrupt mode), catching the netlink event within
1ms of ARP resolution. (`293b818`)

```rust
if available == 0 {
    maybe_wake_rx(binding, false, now_ns);
    retry_pending_neigh(...);  // NEW — check buffered packets
    counters.flush(&binding.live);
    return did_work;
}
```

### 7. No Session Created on MissingNeighbor

**Problem:** When a TCP SYN hit `MissingNeighbor`, the session was
never created. The SYN was buffered and later forwarded (after ARP
resolved), but the SYN-ACK from the target had no matching forward
session. The SYN-ACK went through session miss → policy check, and
with default-deny policy for WAN→LAN, it was dropped.

**Fix:** Create the session immediately on `MissingNeighbor`, before
buffering the packet. The session stores the NAT decision so the
SYN-ACK's reverse lookup finds it via `install_reverse_session_from_forward_match`. (`9584447`)

## Architecture: Cold Start Flow (Final)

```
1. SYN arrives on ge-0-0-1 → XDP shim → XSK → helper RX
2. Session miss → policy permit → SNAT → FIB lookup
3. FIB: next-hop $IPERF_TARGET4 on ge-0-0-2.80
4. Neighbor lookup: not in dynamic_neighbors → MissingNeighbor

5. CREATE SESSION (NAT decision stored for reverse SYN-ACK lookup)
6. ICMP PROBE: socket(SOCK_RAW, IPPROTO_ICMP) + SO_BINDTODEVICE
   → kernel sends ICMP echo → triggers ARP on ge-0-0-2.80
   → ARP reply arrives → kernel learns neighbor → RTM_NEWNEIGH
7. BUFFER PACKET: hold UMEM frame in pending_neigh queue

8. Netlink monitor thread: recv() → RTM_NEWNEIGH → update dynamic_neighbors
9. Worker poll (1ms): rx.available() == 0 → retry_pending_neigh()
   → neighbor found in dynamic_neighbors → rewrite frame → XSK TX
10. SYN reaches $IPERF_TARGET4 → SYN-ACK comes back
11. SYN-ACK: session hit (forward NAT match) → reverse session created
    → forwarded to cluster-host via XSK TX
12. ACK: session hit → TCP established → data flows at line rate
```

**Total cold latency target: ~2ms** (ARP/NDP roundtrip + netlink +
retry) — **currently measured ~3.371s** under a cold neighbor cache
because of the 260 ms-probe vs 2000 ms-timeout gap; mitigation tracked
by #1636 (see accuracy note at the top of this file).

## Performance Results

| Metric | Before | After |
|--------|--------|-------|
| Cold TCP connect (after ARP flush) | Infinite timeout | ~2ms target; **~3.371s measured** (#1636) |
| Cold iperf3 IPv4 (8 streams, 5s) | 0 Gbps (timeout) | 20.1 Gbps |
| Cold iperf3 IPv6 (8 streams, 5s) | 0 Gbps (broken) | 20.0 Gbps |
| Warm iperf3 (8 streams, 10s) | 23+ Gbps | 23+ Gbps |
| Fill ring bootstrap | Failed (0/12 queues) | 12/12 queues |
| Neighbor resolution | 1-5s (Go snapshot) | ~2ms target; gated by 260 ms-probe/2000 ms-timeout gap, ~3.371s cold today (#1636) |

## Files Changed

| File | Changes |
|------|---------|
| `userspace-dp/src/afxdp.rs` | Buffer-and-retry, ICMP probe, netlink monitor, session-on-miss, retry on empty RX |
| `userspace-dp/src/afxdp/bind.rs` | Pre-bind fill ring prime, SO_BUSY_POLL tuning |
| `userspace-dp/src/main.rs` | Global busy_poll sysctls |
| `userspace-xdp/src/lib.rs` | XDP_PASS for non-IP, heartbeat gating removal |
| `pkg/dataplane/userspace/manager.go` | Kernel address sync, NAPI bootstrap after rebind, VLAN sub XDP skip |
| `pkg/dataplane/compiler.go` | Skip XDP on VLAN sub-interfaces |
| `pkg/dataplane/loader.go` | VlanSubInterfaces tracking |
| `pkg/daemon/daemon.go` | Session sync timeout tuning |

## Key Learnings

1. **mlx5 zero-copy XDP_PASS breaks VLAN demux** — the ZC-to-SKB
   conversion path doesn't call `vlan_do_receive()`. ARP/NDP replies
   on VLAN interfaces must be resolved through the kernel's own stack
   (ICMP socket probe), not through XDP_PASS.

2. **AF_PACKET on VLAN sub-interfaces is unreliable** — `send()` and
   `sendto()` report success but frames are silently dropped. The
   kernel's VLAN egress path with TX offload expects the tag in
   descriptor metadata, not in the frame payload.

3. **SOCK_DGRAM IPPROTO_ICMP sendto() fails with EINVAL** — despite
   the socket creation succeeding. Always use SOCK_RAW for ICMP/ICMPv6
   probes. Set `IPV6_CHECKSUM` for ICMPv6 auto-checksum.

4. **Buffer retry must run on empty RX polls** — the XSK poll loop's
   early return on `available == 0` skips end-of-batch processing.
   Buffered packets sit idle until the next RX packet arrives (~1s for
   TCP retransmit). Checking the buffer on every poll wake (1ms) is
   critical for sub-10ms cold start.

   **But checking the buffer is not the same as walking it (#7156).**
   Because this runs on every poll (twice — the RX-empty branch and the
   post-batch call), the per-sweep cost is multiplied by the poll rate.
   The sweep used to snapshot every unresolved key into a fresh `Vec`
   and walk all of them, bounded only by an empty-map early-out:

   | pending keys | ns/sweep | Vec bytes/sweep |
   |--------------|----------|-----------------|
   | 0            | 8        | 0               |
   | 1 024        | 40 709   | 24 576          |
   | 4 096 (cap)  | 182 207  | 98 304          |

   A healthy binding holds zero pending keys and pays 8 ns, which is why
   this never showed up in profiling. At the `MAX_PENDING_NEIGH` cap it
   is ~364 us and ~196 KiB per poll iteration — an idle worker core
   spent on hops whose packets are already being dropped and negatively
   cached, and reachable by scanning distinct unresolved next-hops.

   It is now deadline-ordered and budgeted (`afxdp/neigh_schedule.rs`):
   nothing due costs one heap peek (~20 ns, flat in the population), and
   at most `PENDING_NEIGH_SWEEP_BUDGET` keys are serviced per sweep.

   Freshness is preserved by a separate mechanism, because deadline
   order alone would break it: a key has nothing scheduled between its
   last probe (queued + 260 ms) and its timeout, so a neighbour
   resolving at 300 ms would go unnoticed until the packet was DROPPED
   as never-resolved. `ShardedNeighborMap` therefore carries an insert
   generation, and a sweep that observes it change walks every pending
   key on that sweep — so a resolved packet dispatches with exactly the
   latency it always had. Filling the pending cap resolves nothing, so
   it triggers no walks: the attack path pays the bounded cost, the
   legitimate path pays none of it.

5. **Create sessions on MissingNeighbor** — without the forward session,
   the reverse direction (SYN-ACK) can't find the NAT match and gets
   policy-denied. The session must exist before the SYN-ACK arrives.

## #1769 — Negative-cache stuck state + on-demand resolver (immediate fix)

The #1651 dead-host negative cache (`afxdp/neg_neigh.rs`) fast-fails a
SYN to a negatively-cached `(egress_ifindex, next_hop)` **before** the
ARP probe and the `pending_neigh` buffer
(`poll_descriptor/mod.rs` MissingNeighbor arm). That is correct for a
genuinely dead host — and #6710 is the case where the dst is not a host at
all: an IPsec `xfrmi` egress has no link-layer address, so the
resolved-neighbor-wins escape can never fire and the cache is never allowed
to arm for it (`ForwardingState.lladdrless_egress`). It also produced a
stuck state for a
directly-connected, **outbound-only** target (e.g. the smoke iperf3 dst
`$IPERF_TARGET4` on `ge-0-0-2.80`):

- `dynamic_neighbors` lost the entry — a transient kernel
  FAILED/INCOMPLETE/DELNEIGH during revalidation removes it
  (`neighbor.rs::parse_neighbor_msg`), or a good RTM_NEWNEIGH was
  dropped (the monitor swallows `recv()<=0` and the full dump is
  startup-only).
- The 3 s negative entry was armed, so every new SYN fast-failed with
  **nothing** re-probing or re-buffering the dst. The kernel's valid
  DELAY/STALE lladdr was unusable because the hot path refuses an
  on-demand kernel read (`forwarding/mod.rs::lookup_neighbor_entry`).
- Result: repeated 3 s connect blackouts until the kernel independently
  re-validated and emitted a fresh RTM_NEWNEIGH.

**Fix (`afxdp/neighbor_resolver.rs`):** on a negative-cache fast-fail the
worker enqueues the dst into ONE **shared, per-key, rate-limited**
resolver (the `neg_neigh_cache` is per-binding × 6 WAN workers, so a
per-binding GET would be 6× rtnl). The resolver thread holds a persistent
netlink socket and, off the hot path:

1. **rate-limits per `(ifindex, hop)`** (1 s window) so a SYN storm fires
   at most one GET/probe per key — no probe storm;
2. issues a **single-key `RTM_GETNEIGH`** (`NLM_F_REQUEST` + `NDA_DST`,
   no dump flags — NOT the RTNL-mutex dump path);
3. caches the lladdr into `dynamic_neighbors` **only if REACHABLE /
   PERMANENT** AND the global neighbor epoch
   (`neighbors.generation`) has not advanced since enqueue — the
   **epoch guard** that defeats the out-of-order race where a concurrent
   monitor FAILED/DELNEIGH removal would be clobbered by a late stale
   insert;
4. on **STALE / DELAY / PROBE** (the live wedge signature) does NOT cache
   the unconfirmed MAC — it fires `trigger_kernel_arp_probe` to force
   kernel revalidation and lets the resulting confirmed multicast
   RTM_NEWNEIGH populate the map;
5. on **FAILED / INCOMPLETE / no-reply** caches nothing and revokes any
   stale dynamic entry (immediate-revocation firewall posture) plus a
   probe.

This preserves the #1651 dead-host storm defense (packets still
fast-fail; no `pending_neigh` slot consumed) and never forwards to an
unconfirmed MAC. The hot path only pays a non-blocking `try_send` on the
negative fast-fail (not per-packet).

**Observability (`neighbor_resolver_*` Prometheus series):** queue depth
(gauge), GET attempts / resolved / failures, probe-on-stale, epoch
rejects, enqueue drops, disconnected. Before #1769 the only neighbor
metrics were the two `neighbor_warm_*` counters, so the stuck state was
invisible.

**Latency observability (#1772 — `neighbor_*_seconds` histograms +
counters):** #1769 added COUNT metrics but no TIMING, so the operator's
*intermittent* slow-new-connection symptom stayed invisible (warm + cold
connects measured ~4 ms with resolver counters at 0). #1772 adds cheap,
fixed-bucket, shared-aggregate latency histograms:

- `xpf_userspace_neighbor_pending_dwell_seconds` — how long a buffered
  packet sat in the `pending_neigh` queue before its neighbor resolved
  and it was dispatched (`now_ns - pkt.queued_ns` at the
  `retry_pending_neigh` success path). THE key metric.
- `xpf_userspace_neighbor_resolver_get_rtt_seconds` — resolver single-key
  RTM_GETNEIGH round-trip (request sent → reply read) on the resolver
  thread.
- `xpf_userspace_neighbor_pending_timeout_drops_total` — pending packets
  dropped after `PENDING_NEIGH_TIMEOUT` without resolving.
- `xpf_userspace_neighbor_pending_max_depth` — high-water mark of the
  pending-neigh queue depth (also surfaced in `show system buffers`).

Bucket layout: 16-bucket pow2-ns ladder (bucket `i` upper bound
`2^(16+i)` ns; bucket 15 = `+Inf`). The 3 s blackout class from #1769
lands in the multi-second `+Inf` tail. Cost is near-zero — these fire
only on the rare neighbor-miss/retry sweep and the single resolver
thread, never on the forwarded-packet fast path; the dwell reuses the
existing monotonic `queued_ns` timestamp (one sub + one bucket
`fetch_add`). The probe→revalidate latency (#1772 metric 4) is a known
gap: the probe fires on the resolver/retry thread but the REACHABLE
confirmation arrives asynchronously on the netlink MONITOR thread with no
per-key request/reply correlation, so it is not cleanly measurable
in-process without net-new shared monitor↔resolver state.

**Deferred to a follow-up (plan §10a):** the full per-key resolver state
machine — per-key pending bound, per-key (not global) epoch, backoff that
coalesces all pressure into one in-flight GET, and a throttled
ENOBUFS-triggered family re-dump for the silent netlink-desync (D4). The
immediate fix above closes the live wedge; it does not yet add the
ENOBUFS re-dump.
