# Userspace AF_XDP Dataplane Architecture

## Overview

The userspace dataplane is a Rust-based packet forwarding engine that
processes transit traffic via AF_XDP sockets, bypassing the kernel
networking stack for stateful firewall processing. Under #1373 it is the
primary/default target for dataplane development and routine validation. It
still runs alongside the legacy BPF XDP pipeline while retirement blockers are
closed.

This document tracks the current `master` architecture. It is not a claim
that every supported configuration already reaches feature or performance
parity with the legacy eBPF dataplane. For the exact admission gate, use
[`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md). For active
debugging entry points, use [`userspace-debug-map.md`](userspace-debug-map.md).

```
                        ┌─────────────────────────────────┐
                        │          xpfd (Go)             │
                        │  ┌───────────┐  ┌────────────┐  │
                        │  │  Config   │  │  Cluster    │  │
                        │  │  Store    │  │  Sync       │  │
                        │  └─────┬─────┘  └──────┬─────┘  │
                        │        │               │         │
                        │  ┌─────▼───────────────▼─────┐  │
                        │  │  Userspace Manager         │  │
                        │  │  (snapshot, lifecycle)      │  │
                        │  └─────┬─────────────────────┘  │
                        └────────┼────────────────────────┘
                    Unix socket  │  (JSON control protocol)
                        ┌────────▼────────────────────────┐
                        │  xpf-userspace-dp (Rust)       │
                        │  ┌────────┐ ┌────────┐          │
                        │  │Worker 0│ │Worker 1│ ...      │
                        │  │ AF_XDP │ │ AF_XDP │          │
                        │  └───┬────┘ └───┬────┘          │
                        └──────┼──────────┼───────────────┘
                               │          │
                    ┌──────────▼──────────▼──────────┐
                    │       Kernel (mlx5 driver)      │
                    │  ┌──────────────────────────┐   │
                    │  │  XDP Shim (BPF program)   │   │
                    │  │  redirect → XSK socket    │   │
                    │  └──────────────────────────┘   │
                    │  ┌──────┐  ┌──────┐             │
                    │  │ NIC  │  │ NIC  │  25G mlx5   │
                    │  │ LAN  │  │ WAN  │  ConnectX-5  │
                    │  └──────┘  └──────┘             │
                    └─────────────────────────────────┘
```

## Component Architecture

### 0. Operator Buffer Telemetry

`show system buffers` uses the userspace helper status path when the
active dataplane implements `Status() (userspace.ProcessStatus, error)`;
it does not depend on BPF map occupancy for userspace mode. The rendered
rows are aggregate AF_XDP UMEM frame and TX-ring utilization, with
`WARNING` at >=80% and `CRITICAL` at >=90%. `show system buffers detail`
adds per-binding rows after the aggregates so a hot binding is visible
even when total aggregate usage is low. Both userspace buffer commands
preserve the legacy `Active sessions` footer.

The bounded source fields are
`ProcessStatus.PerBinding[].umem_total_frames`,
`umem_inflight_frames`, `tx_ring_capacity`, and `outstanding_tx`; the
same fields on `ProcessStatus.Bindings[]` are accepted as a fallback for
older helper status snapshots. If neither path publishes capacity, the
CLI reports the missing status fields rather than showing BPF-map
metrics for userspace buffers.

### 1. XDP Shim (`userspace-xdp/src/lib.rs`)

A minimal BPF program attached at the NIC driver level that decides
whether each packet should be processed by userspace or the existing
kernel BPF pipeline.

**Packet decision flow:**

```
Packet arrives at NIC
  │
  ├─ Non-IP (ARP, etc.) ──────────────────► cpumap → kernel stack
  ├─ Multicast / broadcast ────────────────► cpumap → kernel stack
  ├─ Local destination ────────────────────► cpumap → kernel stack
  ├─ GRE / ESP / explicit fallback cases ──► tail-call → legacy XDP pipeline
  │
  ├─ Has active session in BPF map? ───YES─► XDP_REDIRECT → XSK socket
  │
  ├─ Session miss but still transit traffic ─► XDP_REDIRECT → XSK socket
  │
  └─ Binding/heartbeat failure on DP-managed interface ─► DROP or explicit fallback
```

**Key design decisions:**

- **Session-aware, not session-only redirect**: live sessions skip extra
  local/interface-NAT checks, but transit session misses are still redirected
  so the Rust dataplane can perform first-packet policy/NAT/FIB evaluation.

- **cpumap for kernel pass-through**: In AF_XDP zero-copy mode, XDP_PASS
  permanently consumes UMEM frames (the kernel holds them in SKBs). The
  shim uses `bpf_redirect_map` to a cpumap instead, which immediately
  frees the XSK frame while still delivering the packet to the kernel
  networking stack.

- **Fail closed on dead bindings**: if a binding is missing, not ready, or
  its heartbeat is stale on a userspace-managed interface, the shim drops
  rather than blindly passing packets into the kernel path and creating
  spurious RST/black-hole behavior.

- **Heartbeat watchdog**: Each worker writes a timestamp to a BPF array
  map every 250ms. The shim checks freshness (5s timeout) and refuses
  to redirect if the worker appears stalled.

### 2. Rust Dataplane Process (`userspace-dp/`)

The main forwarding engine. Spawned by xpfd as a child process,
communicates over a Unix domain socket.

#### Process Structure

```
main thread
  ├── Control socket listener (JSON protocol)
  ├── Coordinator (manages workers and state)
  │
  ├── Worker 0 ──► AF_XDP binding (ge-0-0-1, queue 0)
  │                AF_XDP binding (ge-0-0-2, queue 0)
  │
  ├── Worker 1 ──► AF_XDP binding (ge-0-0-1, queue 1)
  │                AF_XDP binding (ge-0-0-2, queue 1)
  │
  ├── ... (one worker per RSS queue)
  │
  ├── Sync thread (session delta export)
  └── io_uring thread (state file persistence)
```

Each worker thread is pinned to a CPU and processes all packets from
its assigned RSS queues. Workers are independent — no locks on the
forwarding hot path.

#### Per-Packet Processing Pipeline

```
RX from AF_XDP ring (up to 256 frames per batch, 4 batches per poll)
  │
  ├─ Parse XDP metadata (magic, version, 5-tuple, offsets)
  ├─ Validate config/FIB generation (stale → exception)
  │
  ├─ Session lookup (FxHashMap, O(1))
  │   ├─ HIT: Use cached forwarding decision
  │   ├─ SHARED HIT: Promote from shared table (HA peer)
  │   ├─ NAT REVERSE: Repair reply path from forward entry
  │   └─ MISS: Full policy + NAT + FIB evaluation
  │
  ├─ For session miss:
  │   ├─ Zone pair determination (ingress → egress zone)
  │   ├─ Policy evaluation (ordered rule match)
  │   │   └─ Deny → recycle frame, continue
  │   ├─ NAT matching (SNAT rules by zone/prefix)
  │   ├─ FIB resolution (route + neighbor + VLAN)
  │   └─ Install session (forward entry + NAT reverse index)
  │
  ├─ HA enforcement
  │   ├─ Check RG active status
  │   ├─ Watchdog timestamp freshness
  │   └─ Fabric redirect if needed
  │
  ├─ Apply NAT rewrite (incremental L3/L4 checksum)
  ├─ Build egress frame (MAC rewrite, VLAN tag)
  │
  └─ TX submission
      ├─ Same binding: in-place UMEM rewrite when possible
      └─ Cross binding: copy into target binding UMEM on the common path
```

#### AF_XDP Ring Management

Each binding manages four rings:

```
┌─────────────┐     ┌─────────────┐
│  Fill Ring   │◄────│  Free Pool  │  Userspace → Kernel
│ (empty bufs)│     │  (recycled  │  "Here are empty frames
└──────┬──────┘     │   frames)   │   for you to fill"
       │            └─────────────┘
       ▼
┌─────────────┐
│  RX Ring     │  Kernel → Userspace
│ (received)  │  "Here are received packets"
└──────┬──────┘
       │ process + rewrite
       ▼
┌─────────────┐
│  TX Ring     │  Userspace → Kernel
│ (to send)   │  "Please transmit these"
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Completion   │  Kernel → Userspace
│   Ring       │  "These TX frames are done,
└─────────────┘   you can reuse them"
```

**Frame lifecycle:**
1. Allocate UMEM frames at startup (ring_entries × 4096 bytes each)
2. Submit empty frames to fill ring
3. Kernel fills frames with received packets, posts to RX ring
4. Worker reads RX, processes, rewrites in-place or copies to TX
5. Submit to TX ring, kernel transmits
6. Completion ring returns transmitted frame offsets
7. Recycle completed frames back to fill ring

**Zero-copy vs copy mode:**
- Zero-copy: NIC DMA writes directly into UMEM. No kernel memcpy.
  Requires driver support and safe kernel-pass handling.
- Copy mode: Kernel copies packet data into UMEM. The current tree still
  contains mlx5/copy-mode mitigations and debugging around fill-ring pressure,
  so do not read "AF_XDP" as meaning "always zero-copy" on current `master`.

#### Session Table (`session.rs`)

Per-worker hash table using `FxHashMap` (fast non-cryptographic hash).

```
SessionKey {
    addr_family: u8,     // AF_INET or AF_INET6
    protocol: u8,        // TCP=6, UDP=17, ICMP=1
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}
    │
    ▼
SessionEntry {
    decision: SessionDecision {
        resolution: ForwardingResolution {
            disposition,     // ForwardCandidate, LocalDelivery, etc.
            egress_ifindex,
            tx_ifindex,
            neighbor_mac,
            src_mac,
            tx_vlan_id,
        },
        nat: NatDecision {
            rewrite_src,     // Option<(IpAddr, u16)>
            rewrite_dst,     // Option<(IpAddr, u16)>
        },
    },
    metadata: SessionMetadata {
        ingress_zone,
        egress_zone,
        owner_rg_id,
        is_reverse,
        synced,              // true = from HA peer
    },
    last_seen_ns: u64,
    closing: bool,           // FIN/RST received
}
```

**NAT reverse index:** A secondary index maps reply 5-tuples to their
forward session keys. When a reply packet arrives (e.g., from a SNAT'd
connection), the reverse index resolves the original session without
full table scan.

**Protocol timeouts:**
| Protocol | Active | Closing (FIN/RST) |
|----------|--------|-------------------|
| TCP      | 300s   | 30s               |
| UDP      | 60s    | —                 |
| ICMP     | 15s    | —                 |
| Other    | 30s    | —                 |

#### NAT (`nat.rs`)

Stateless per-packet NAT rewrite. Session table holds the NAT decision;
the NAT module applies it:

- **SNAT (interface mode):** Rewrite source IP to egress interface address.
  Source port preserved.
- **SNAT (pool mode):** Rewrite source IP to a configured source pool address
  and allocate a source port from the pool range. By default, pool address
  selection is round-robin within the packet address family. With global source
  NAT `address-persistent`, the userspace dataplane hashes a domain tag,
  address family, and canonical source IP bytes with SHA-256 to choose a stable
  pool index. This is sticky within the current pool size and order; changing
  either can remap existing source IPs to different pool addresses.
  This is intentionally documented as a userspace-v1 algorithm, not
  mixed-backend new-flow parity: legacy eBPF and current DPDK use C-word IPv4
  modulo and IPv6 lane-XOR selection. Active synced sessions carry the chosen
  translated tuple, but new allocations after backend rollback may choose a
  different pool address. Pool-mode rules with missing pools, empty pools,
  invalid port ranges, malformed addresses, or no address for the packet
  family fail-closed at the current `poll_descriptor.rs` source-NAT call sites
  before session creation or forwarding, and record recent-exception reasons
  such as `source_nat_pool_missing`, `source_nat_pool_empty`, and
  `source_nat_pool_invalid_port_range`. Per-pool `persistent-nat` lease reuse
  is not part of the userspace-v1 runtime contract yet because the snapshot
  does not carry persistence mode and the Rust allocator does not consult the
  Go `PersistentNATTable`.
- **Checksum update:** Incremental RFC 1624 checksum adjustment for
  IP header + TCP/UDP pseudo-header. Avoids full recomputation.

#### Policy Evaluation (`policy.rs`)

Ordered rule matching against zone pairs, address books, and applications:

```
for rule in rules:
    if rule.inactive:
        continue
    if rule.from_zone matches ingress_zone
       AND rule.to_zone matches egress_zone
       AND rule.source matches src_ip
       AND rule.destination matches dst_ip
       AND rule.application matches (proto, src_port, dst_port):
        return rule.action  // Permit or Deny
return default_deny
```

Address book entries support IPv4/IPv6 prefixes. Application matching
supports protocol + port ranges. `rule.inactive` is the policy-scheduler result
published by the Go daemon; inactive scheduled rules are skipped before any
match side effects or counters.

#### Slow Path (`slowpath.rs`)

A TUN device (`xpf-usp0`) for packets that need kernel processing:

- ICMP reject responses (policy deny with reject action)
- Packets that fail forwarding resolution
- Rate-limited: 2000 pps, 16 MB/s (prevents flooding kernel)
- Async writes via io_uring (non-blocking on worker thread)
- Bounded channel (256 depth) between enqueue and writer thread

### 3. Go Manager (`pkg/dataplane/userspace/manager.go`)

The Go side manages the Rust process lifecycle and feeds it configuration.

#### Snapshot Protocol

On every config commit, route change, or HA state transition, the
manager builds a `ConfigSnapshot` and sends it to the Rust process:

```
ConfigSnapshot {
    zones:           [{name, interfaces}]
    interfaces:      [{ifindex, name, mac, addresses, vlan_id, zone}]
    fabrics:         [{ifindex, name, mac, peer_mac, fib_ifindex}]
    neighbors:       [{ifindex, ip, mac}]
    routes:          [{prefix, next_hop, ifindex, table}]
    policies:        [{rule_id, from_zone, to_zone, src/dst, apps, action,
                       scheduler_name, inactive}]
    source_nat_rules:[{from_zone, to_zone, src/dst, interface/pool metadata}]
    flow:            {allow_dns_reply, allow_embedded_icmp}
    map_pins:        {xsk_map, heartbeat_map, sessions_map}
    ha_groups:       [{rg_id, active, watchdog_ts}]
}
```

#### Capability Check

The manager evaluates the active config to determine if the userspace
dataplane can handle it. Unsupported features cause automatic fallback
to the legacy kernel BPF pipeline:

The current supported/gated split is maintained in
[`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md). In broad terms,
the Rust path now owns stateful forwarding, zone/global policies, application
matching, interface-mode SNAT, DNAT, static NAT, NAT64, NPTv6, firewall
filters, flow export, TCP MSS clamping, configurable timeouts, VLAN handling,
route/neighbor lookup, and HA/session-delta ingestion.

Remaining explicit gates include SYN-cookie-dependent screen behavior,
three-color policers, port mirroring, dataplane event parity, and the residual
#1377 SNAT pool contract for per-pool `persistent-nat`, allocator exhaustion
counters, and mixed-backend rollback constraints.

Policy scheduler state is no longer a propagation gap: #1396 carries scheduler
state into the userspace snapshot and Rust policy evaluator. #1378 remains a
retirement blocker only for the residual contract around hit-counter lifetime,
strict missing-scheduler commit behavior, and integration/failover evidence.
#1377 now preserves unusable pool-mode source-NAT rules in the snapshot and
fails closed at the `poll_descriptor.rs` source-NAT call sites for missing
pools, empty pools, invalid pool inputs, wrong-family-only pools, or allocator
failure. #1377 still owns persistent-NAT lease reuse, allocator observability,
live-port exhaustion counters, and the documented mixed-backend rollback
boundary. #1386 landed
userspace buffer/status rendering; #1380 still owns
retirement of the remaining BPF-map-oriented operator surface.

### 4. HA Cluster Integration

The userspace dataplane participates in the chassis cluster HA:

```
┌──────────────────┐     fabric link      ┌──────────────────┐
│  fw0 (PRIMARY)   │◄───────────────────►│  fw1 (BACKUP)    │
│                  │                      │                  │
│  xpfd ◄──────────── session sync ────────► xpfd       │
│    │             │                      │    │             │
│    ▼             │                      │    ▼             │
│  userspace-dp    │                      │  userspace-dp    │
│  [workers 0-5]   │                      │  [workers 0-5]   │
│  sessions: local │                      │  sessions: synced│
└──────────────────┘                      └──────────────────┘
```

**Session synchronization flow:**

1. Worker creates forward session → emits `SessionDelta::Open`
2. Coordinator collects deltas from all workers
3. xpfd drains deltas via control socket
4. Cluster sync sends deltas to peer over TCP fabric link
5. Peer xpfd pushes received sessions into userspace-dp
6. Peer workers install as "synced" sessions (no further replication)

**Failover handling:**

- VRRP detects primary failure (~60ms with 30ms intervals)
- New primary activates RGs → `UpdateRGActive(rg, true)`
- Workers start forwarding for activated RGs
- Synced sessions from peer are promoted on first packet match
- XDP shim session map allows immediate redirect for promoted sessions

**Fabric redirect:**

When a packet arrives on the backup node but the session owner is the
primary (or vice versa during failback), `try_fabric_redirect()` sends
the packet across the fabric link to the correct node.

## Performance Architecture

### CPU Layout (8 vCPU, 25G mlx5)

```
CPU 0: Worker 0 + NAPI (ge-0-0-1 queue 0, ge-0-0-2 queue 0)
CPU 1: Worker 1 + NAPI (ge-0-0-1 queue 1, ge-0-0-2 queue 1)
CPU 2: Worker 2 + NAPI (ge-0-0-1 queue 2, ge-0-0-2 queue 2)
CPU 3: Worker 3 + NAPI (ge-0-0-1 queue 3, ge-0-0-2 queue 3)
CPU 4: Worker 4 + NAPI (ge-0-0-1 queue 4, ge-0-0-2 queue 4)
CPU 5: Worker 5 + NAPI (ge-0-0-1 queue 5, ge-0-0-2 queue 5)
CPU 6: xpfd (Go daemon) + sync
CPU 7: main thread + io_uring + kernel
```

### Hot-Path Optimizations

| Technique | Impact | Description |
|-----------|--------|-------------|
| Lock-free forwarding | Critical | No mutexes on per-packet path; atomics for counters |
| FxHashMap sessions | ~1.7% CPU | Non-cryptographic hash for O(1) session lookup |
| Batched ring ops | ~2% CPU | Process 256 frames per RX batch, batch TX submissions |
| In-place UMEM rewrite | ~11% CPU saved | Same-binding forwarding without memcpy |
| Incremental checksums | ~1% CPU | RFC 1624 differential update vs full recomputation |
| Compile-time debug gate | ~0% overhead | `cfg!(feature = "debug-log")` compiles out all debug |
| Batched counters | ~0.5% CPU | Aggregate per-packet counts, flush atomically |
| Cached resolution | ~0.8% CPU | Reuse forwarding decision from session entry |
| NAPI busy polling | Latency | `SO_BUSY_POLL` reduces interrupt-to-userspace latency |

### Throughput Profile (23 Gbps, 12 streams)

| Component | CPU% | Notes |
|-----------|------|-------|
| poll_binding (user) | 22% | Main packet processing loop |
| memcpy (libc AVX-512) | 8% | Cross-UMEM frame copy (unavoidable) |
| XDP BPF programs | 7% | XDP shim + xdp_policy coordination |
| mlx5 driver (NAPI) | 12% | NIC receive/transmit processing |
| Interrupt handling | 4% | IRQ entry/exit |
| Syscalls (sendto) | 3% | AF_XDP ring kicks |
| Forwarding funcs | 8% | NAT, sessions, resolution, TX drain |
| Other kernel | 4% | TSC reads, XSK peek, fput |

### Scaling Characteristics

| Workers | RSS Queues | Throughput | Notes |
|---------|------------|------------|-------|
| 4 | 5 | 20 Gbps | CPU-bound (4 vCPU VM) |
| 6 | 6 | 23 Gbps | Near line rate (8 vCPU VM) |

Per-worker ceiling: ~4-5 Gbps (includes kernel NAPI overhead on same CPU).
RSS queue count should match worker count for optimal distribution.

## Configuration

```junos
system {
    dataplane-type userspace;
    dataplane {
        binary /usr/local/sbin/xpf-userspace-dp;
        control-socket /run/xpf/userspace-dp.sock;
        state-file /run/xpf/userspace-dp.json;
        workers 6;
        ring-entries 16384;
    }
}
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| workers | 1 | Number of AF_XDP worker threads |
| ring-entries | 1024 | RX/TX/fill/completion ring size per binding |
| binary | — | Path to Rust binary |
| control-socket | — | Unix socket for control protocol |
| state-file | — | JSON state persistence path |

**Tuning guidelines:**
- Set `workers` to match NIC RSS queue count (`ethtool -L <dev> combined N`)
- Set `ring-entries` to 16384 for ≥20 Gbps throughput.
  UMEM cost per binding at ring=16384:
    - mlx5 / native XDP: `reserved_tx (min(ring/2, 8192)) + 2 × ring_entries` = `8192 + 32768 = 40960 frames × 4 KB = 160 MB per binding`
    - virtio_net: `ring_entries + 2 × ring_entries` = `3 × 16384 × 4 KB = 192 MB per binding`
  `binding_frame_count_for_driver` in `userspace-dp/src/afxdp/bind.rs` is authoritative.
  At 8192, `iperf3 -P 12 @ 25 Gbps` sees 92-170K retrans/30s and median 16.9 Gbps due
  to kernel-side TX ring fill stalls (`ethtool -S` shows `tx_xsk_full` accumulating).
  Raising to 16384 dropped retrans to 0-1900/30s and lifted the median to 21.5 Gbps
  on the loss:xpf-userspace-fw test cluster (#774). **DO NOT raise to 32768** —
  measurement on the same workload showed regression to 11-18 Gbps with 17-37K retrans,
  likely TLB pressure + excess UMEM memset at bind.
- **Hugepages (REQUIRED for ring ≥ 16384)**: UMEM mapping tries `MAP_HUGETLB` (2 MB
  pages) first, falls back to `MADV_HUGEPAGE` (advisory, kernel may or may not promote).
  At ring=16384 × 4 KB pages = 40960 TLB entries per binding × 6 bindings = 245K TLB
  entries — that's larger than a typical CPU's TLB can hold, and throughput will stall
  in TLB-miss latency. With 2 MB hugepages the same UMEM needs ~480 TLB entries,
  fitting comfortably in the iTLB/dTLB.

  **Reserve via `/etc/sysctl.d/99-xpf-hugepages.conf`:**
  ```
  vm.nr_hugepages = 600
  ```
  Apply with `sysctl --system` (or reboot). 600 × 2 MiB = 1.2 GiB covers one NIC's
  UMEM at ring=16384. Verify with `grep HugePages_ /proc/meminfo` — `HugePages_Total`
  must be ≥ 560 before xpfd starts, else `MAP_HUGETLB` will fail silently and the
  daemon will fall back to THP which is not guaranteed to promote all pages.

  **Measurement on loss:xpf-userspace-fw0 (8 GiB VM, kernel 7.0.0-rc7, mlx5 ConnectX):**
    - ring=8192 (no hugepages needed): median 16.9 Gbps, stddev 1.7
    - ring=16384 without hugepages: median 20.4 Gbps, stddev 1.7
    - ring=16384 with 600 hugepages: **median 22.1 Gbps, stddev 1.5** ← campaign target
- Ensure VM has enough vCPUs: workers + 2 (daemon + kernel headroom)
- Ensure VM has enough RAM: `workers × bindings × 160 MB + 2 GB` base (at 16384 ring,
  mlx5 driver; 192 MB for virtio_net)

## Limitations and Mixed Boundaries

This section is a high-level architecture note. The authoritative current gate
is [`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

**Still explicitly gated or incomplete for eBPF retirement:**
- Source NAT pool mode: userspace-v1 deterministic pool selection and
  fail-closed runtime handling for missing pools, empty pools, invalid pool
  inputs, wrong-family-only pools, and allocator failures have landed. #1377 is
  still required for per-pool `persistent-nat` lease reuse,
  pool allocation/exhaustion counters, and the mixed-backend rollback test
  boundary.
- SYN-cookie flood protection closeout: #1374 still owns bounded SYN-ACK/RST
  TX, HA-safe secrets, integration evidence, and gate removal.
- RFC 2697/2698 three-color policer closeout: #1375 now preserves
  token/counter state across compatible in-process snapshot refreshes. It still
  owns the sharded/packed state decision, HA/restart continuity decision,
  non-drop color actions, and integration/perf evidence beyond the admitted
  color-blind `then discard` slice.
- Port mirroring closeout: #1376 now has bounded userspace runtime admission,
  but still owns mirror-fidelity evidence and forwarding survival under mirror
  pressure before BPF source removal.
- Dataplane event closeout: #1379 still owns end-to-end syslog evidence,
  broader non-PBR filter-log call sites, and richer identity mapping.
- `show system buffers` BPF-map display retirement: #1380. Userspace
  helper-status rendering landed in #1386, but the legacy operator surface
  still needs its Phase 5 cleanup.

**Handled outside the AF_XDP forwarding fast path:**
- ARP, NDP, local management traffic, and other kernel-owned packets are passed
  to cpumap/kernel handling.
- IPsec/XFRM and GRE transit use kernel/pass-through or tunnel-specific
  handling where required.
- Packets failing forwarding resolution can enter the bounded slow path.
