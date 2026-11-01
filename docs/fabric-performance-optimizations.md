# Fabric Forwarding Performance Optimizations

## Current State (2026-04-04)

| Path | -P1 | -P8 |
|------|-----|-----|
| Direct (all RGs same node) | 7.8 Gbps | 23.0 Gbps |
| Fabric (split-RG) | 2.0 Gbps | 3.5 Gbps |

**Correction (#18656, 2026-11-01).** The split-RG row above was measured
on flows that existed before the split, and those flows were not running
on the fabric path the rest of this page describes. The LAN node still
owns such a session and its SNAT, so after the move it fabric-redirects
the forward data already source-translated (`apply_nat_on_fabric`). On
the new WAN owner the packet's tuple is then the session's forward-wire
alias. Until #18656, the flow-cache hit probe could not resolve that
alias. Every hit was refused (`post_hit_session_dead`, all no-record),
the slow path re-resolved the packet and re-seeded the cache, and about
95% of the new owner's packets took that per-packet loop.

Same-session moved-vs-fresh controls, iperf3 `-P8`:

| Cluster | Build | Moved flows | Fresh flows (split first, then load) |
|---|---|---|---|
| tcp | master | 5.8–5.9 Gbit/s | 8.6 Gbit/s |
| tcp | #18656 | 15.3–15.9 Gbit/s | 16.7 Gbit/s |
| loss | master | 1.47–1.58 Gbit/s | VOID (iperf3 `--cport` collision) |
| loss | #18656 | 2.96–3.04 Gbit/s | 3.68–3.77 Gbit/s |

On the fixed build, the new owner serves moved flows from the flow cache:
on tcp, 19.67M cache hits against 19.61M received packets and 0
evictions. That leaves the copy-mode fabric itself (#12655) as the limit.
The loss numbers above come from one session with no master fresh
baseline, so they are not a statement of the loss fabric ceiling. H9's
loss floor stays unset until #18678 re-measures it. Matrix row H9
(`docs/regression-test-matrix.md`) carries the same correction.

## Architecture: How Fabric Redirect Works Today

In strict userspace mode, steady-state fabric transit stays on the AF_XDP
dataplane. It does not rely on `PASS_TO_KERNEL` to bounce transit packets back
into the eBPF forwarding pipeline.

1. The XDP shim classifies packets and redirects transit session hits and
   misses to AF_XDP/userspace.
2. `PASS_TO_KERNEL` is reserved for local-delivery or explicit fallback cases:
   peer-synced local-delivery sessions, ESP, non-native GRE, NDP, and similar
   control-plane traffic.
3. The userspace helper resolves policy, NAT, routing, and HA ownership. If the
   result is `FabricRedirect`, the helper builds the fabric frame itself and
   transmits it through AF_XDP TX.
4. `publish_live_session_entry()` keeps subsequent transit packets on the
   userspace dataplane, so the hot path is flow cache plus `RewriteDescriptor`,
   not `PASS_TO_KERNEL`.
5. `apply_nat_on_fabric` decides whether the userspace helper should NAT the
   packet before fabric TX or preserve the original tuple for later handling on
   the owner side.

### Key implications

- Fabric NAT performance is still a userspace dataplane problem.
- The generic builders and segmentation path still pay real checksum work when
  the descriptor fast path cannot be used.
- Plans that assume "write `PASS_TO_KERNEL` earlier" are solving the wrong path
  for strict userspace fabric transit.

## Fabric NAT Flow (via Userspace Dataplane)

### Outbound: Client -> Server (split-RG: fw0=LAN, fw1=WAN)

```
Client 10.0.61.102:43446 -> 172.16.80.200:5201

1. Arrives on ge-0-0-1 (fw0, LAN)
2. XDP shim -> XSK redirect -> Rust worker
3. Session lookup -> FabricRedirect (RG1/WAN owned by fw1)
4. Rust helper: rewrite MACs for fabric link
   + apply_nat_on_fabric=true -> SNAT (src 10.0.61.102 -> 172.16.80.8)
   + recompute_l4_checksum_ipv4 (full payload walk)
5. TX out ge-0-0-0 (fabric parent, copy-mode XSK -> SKB -> virtio TX)
6. Arrives at fw1 ge-7-0-0 (fabric parent)
7. XDP shim -> XSK redirect -> Rust worker
8. Session lookup -> Forward (RG1/WAN is local)
9. Forwards out ge-7-0-2 (WAN) with src=172.16.80.8:43446
```

### Return: Server -> Client

```
Server 172.16.80.200:5201 -> 172.16.80.8:43446

1. Arrives on ge-7-0-2 (fw1, WAN)
2. XDP shim -> XSK redirect -> Rust worker
3. Session lookup -> FabricRedirect (RG2/LAN owned by fw0)
4. Rust helper: rewrite MACs for fabric link
   + apply_nat_on_fabric=true -> un-SNAT (dst 172.16.80.8 -> 10.0.61.102)
   + recompute_l4_checksum_ipv4 (full payload walk)
5. TX out ge-7-0-0 (fabric parent, copy-mode XSK -> SKB -> virtio TX)
6. Arrives at fw0 ge-0-0-0 (fabric parent)
7. XDP shim -> XSK redirect -> Rust worker
8. Session lookup -> Forward (RG2/LAN is local)
9. Forwards out ge-0-0-1 (LAN) with dst=10.0.61.102:43446
```

## Where the NAT Cost Still Lives

- `build_forwarded_frame_into_from_frame()` still falls back to
  `recompute_l4_checksum_ipv4` for IPv4 NAT plus port-enforcement cases on the
  generic path.
- `segment_forwarded_tcp_frames_from_frame()` has to rebuild TCP checksums per
  segment. Both the IPv4 and IPv6 arms full-recompute
  (`recompute_l4_checksum_ipv4`/`_ipv6`) — the incremental-adjust trick that
  the non-segmented path (item 2 below) uses is **never** valid per segment:
  each segment carries a different payload chunk, a rewritten seq, a cleared
  PSH on non-final segments, and a different pseudo-header length, none of
  which a NAT IP/port delta can capture. A dead-but-wrong incremental IPv4
  branch here was removed in #4384 before it could become a live corruption
  landmine.
- Cache hits still recompute the fabric target binding lookup even though the
  descriptor structure already has space to cache it.

## Actual Bottleneck: Virtio Bridge Throughput

The fabric path runs at 3.5 Gbps with CPUs mostly idle (~2% peak in profiles).
This is NOT a CPU bottleneck — it's the virtio-net bridge throughput between VMs.
(Measured before #18656; see the correction under "Current State": flows that
existed before the split were on a per-packet slow-path loop on the new owner,
so this figure understated the fabric.)

### Contributing factors

1. **Copy-mode XSK on virtio**: The fabric parent uses generic/copy-mode XSK
   (`__xsk_generic_xmit`). Every TX frame allocates an `sk_buff` and copies
   data — there is no zero-copy DMA path on virtio-net.

2. **Virtio TX ring size**: Limited to 256 entries (TX max on QEMU). At high pps,
   the ring fills and the VM must wait for completions before sending more.

3. **Bridge forwarding overhead**: The local bridge between VMs adds per-packet
   overhead for MAC learning, flooding, and sk_buff management.

4. **VM configuration**: vhost-net, NUMA pinning, multiqueue alignment, and CPU
   model settings affect VM-to-VM throughput.

## Optimization Plan

### Phase 1: VM-Level Tuning [LOW effort, potentially HIGH impact]

These are configuration changes, no code required:

1. Verify `vhost-net` is active on the host for both VMs.
2. Pin both VMs to the same NUMA node.
3. Set CPU model to `host` to expose AVX/AES-NI instructions.
4. Increase the virtio TX ring if QEMU supports it.
5. Test MTU 9000 on the bridge itself, not just on the VM interfaces.
6. Disable GSO/LRO inside the guest on the fabric parent if they are adding
   overhead in the pure-virtual path.

Expected improvement: 2-3x if the current ceiling is configuration, not
hardware.

### Phase 2: Tighten the Userspace Fabric/NAT Fast Path [MEDIUM effort]

1. Honor cached `apply_nat_on_fabric` decisions on `FabricRedirect` hits.
   Cached self-target and cross-binding hits must reuse the stored decision
   instead of forcing NAT back on. [COMPLETED — PR #435]
2. Replace the generic IPv4 full recompute path with a combined incremental
   NAT plus expected-port checksum update in
   `build_forwarded_frame_into_from_frame()`. [COMPLETED — incremental checksum
   for non-segmented fabric forwarding, commit `927bfe6f`]
3. Populate `RewriteDescriptor.target_binding_index` for cacheable fabric flows
   so hot hits can skip `fabric_target_index()` while config and FIB generation
   still match.
4. Measure how often `apply_rewrite_descriptor()` falls back to the generic
   builder because of port repair or cross-binding conditions, then widen
   descriptor coverage only where that fallback rate justifies the added code.

### Phase 3: Flow Cache HA Validity Check [COMPLETED — PR #432]

The `cached_flow_decision_valid()` per-packet HA check (1.3% CPU on the direct
path) has been replaced by an inline lease-expiry check in the flow cache stamp.
The `owner_rg_lease_until` field in each flow cache entry is compared against
the current timestamp — O(1) with no BTreeMap lookup. Same correctness
guarantees, better cache locality.

### Phase 4: Reduce Virtio Copy Overhead [LOW effort]

Profile and micro-optimize the copy-mode XSK TX path:

1. **Profile `__xsk_generic_xmit`** during fabric -P8 to find hot spots
2. **Batch TX submissions**: Ensure the Rust helper batches multiple frames
   per `sendto()` syscall to amortize kernel entry/exit overhead
3. **Investigate `XDP_ZEROCOPY`**: Check if virtio-net supports zerocopy mode
   in newer kernels (unlikely on QEMU/KVM, but worth checking)

### Phase 5: Re-profile After Fast-Path Cleanup [LOW effort]

1. Re-run split-RG perf after the Phase 2 and 3 userspace fixes.
2. Determine whether the remaining ceiling is virtio bridge throughput, TX
   completion pressure, binding lookup, or segmentation.
3. Only then decide whether more eBPF-side or VM-side work is worth it.

## Profile Data (Split-RG -P8)

### System-wide (mostly idle)

```
2.0%  pv_native_safe_halt       — CPU idle
1.7%  __irqentry_text_start     — interrupt handling
1.4%  scanobject                — Go GC (daemon, not dataplane)
1.2%  __raw_callee_save_spin    — kernel spinlock
1.2%  worker_loop               — Rust worker (mostly idle)
1.2%  mlx5e_napi_poll           — NIC polling
1.1%  mlx5e_poll_xdpsq_cq       — XDP TX completion
```

The split-RG ceiling still looks dominated by virtualization and queueing, not
raw CPU exhaustion (~95% idle at 3.5 Gbps). That said, the userspace path still
has real NAT and cache-hit overhead worth removing before treating the VM ceiling
as final.

### Direct Path -P8 (23 Gbps, for comparison)

```
15.9%  poll_binding              — packet processing
10.3%  enqueue_pending_forwards  — frame build + segmentation
 2.0%  parse_session_flow        — packet parsing
 1.5%  drain_pending_tx          — TX completions
 1.3%  cached_flow_decision_valid — HA check (per-packet) [now replaced by inline lease check, PR #432]
 1.2%  target_index              — binding lookup
```

## Completed Optimizations

- [x] Virtio RX ring 256->1024 (`raw.qemu rx_queue_size=1024`)
- [x] FabricRedirect flow cache cacheable
- [x] Cache BPF map FDs outside worker loop
- [x] Flow-cache stamp invalidation via config generation, FIB generation, RG
  epoch, and RG lease
- [x] Forward session push to workers on RG activation
- [x] Fabric link preservation in shared_forwarding across snapshots
- [x] Flow cache HA validity: `owner_rg_lease_until` inline check replaces `cached_flow_decision_valid()` BTreeMap lookup (PR #432)
