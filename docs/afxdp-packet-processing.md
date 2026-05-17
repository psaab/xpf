# AF_XDP Userspace Dataplane Packet Processing

> #1373 note: this is the primary packet-processing path for new dataplane
> development and routine validation. References to the legacy BPF pipeline
> below describe explicit fallback/regression boundaries, not the preferred
> implementation target.

## 1. Architecture Overview

The userspace dataplane uses AF_XDP with driver-specific bind/runtime modes to
receive and transmit packets through shared UMEM memory regions.  An XDP shim program
(`xdp_userspace_prog` in `userspace-xdp/src/lib.rs`) runs on each ingress
interface and steers matching packets to AF_XDP sockets via an XSKMAP
(`userspace_xsk_map`).

### Packet steering decision (XDP shim)

The shim checks several conditions before redirecting a packet to userspace:

1. `userspace_ctrl` must be enabled with matching metadata version.
2. Ingress ifindex must be in `userspace_ingress_ifaces` map.
3. A binding must exist in `userspace_bindings` for (ifindex, queue_id) and be
   marked `USERSPACE_BINDING_READY`.
4. The binding's heartbeat (written every 250ms by the worker) must not be
   stale (default 5s timeout).
5. ICMP/ICMPv6 falls back to the legacy BPF pipeline via `userspace_fallback_progs` tail call.
6. Local-destination traffic (matching `userspace_local_v4`/`userspace_local_v6`) passes to kernel.
7. Non-SYN TCP without a live entry in `userspace_sessions` BPF map is dropped
   (not fallen back -- legacy BPF would generate RSTs that kill the real connection).

Packets that pass all checks get a `UserspaceDpMeta` header prepended via
`bpf_xdp_adjust_meta` and are redirected to the AF_XDP socket with
`bpf_redirect_map(&USERSPACE_XSK_MAP, slot)`.

### Per-binding UMEM and rings

Each AF_XDP binding gets its own `WorkerUmem` with independent fill,
completion, RX, and TX rings (`userspace-dp/src/afxdp.rs`).  Frame count is
`2 * ring_entries` (fill) + `reserved_tx_frames` (TX).  Default `ring_entries`
is 1024, configurable via `--ring-entries`.

```
WorkerUmem {
    area: MmapArea,           // mmap'd contiguous UMEM region
    umem: Umem,               // xdpilone UMEM handle
    total_frames: u32,        // fill frames + TX reserve
}
```

### Current runtime mode by driver

Current live behavior on the userspace HA lab is:

1. `mlx5_core` ingress bindings use the UMEM-owner zerocopy path.
2. `virtio_net` fabric bindings use the UMEM-owner copy-mode path with
   `bind_flags=0`.

That split was validated live during the Phase 2 cleanup work.  The failed
`virtio_net` separate-owner probe was removed from the active strategy because
it was not the correct bind contract for this environment.

## 2. The Fill Ring Exhaustion Bug

### Symptoms

Under sustained high throughput (1 Gbps+ TCP), large downloads stall after
partial transfer and the client receives "Connection reset by peer."

### Root cause

The mlx5 driver's AF_XDP RX path requires available frames in the fill ring.
When the userspace poll loop cannot refill frames fast enough, the fill ring
runs dry.  The driver counter `rx_xsk_buff_alloc_err` climbs to 102M+ during
a single transfer.

When no fill ring frames are available, mlx5 falls back to the regular
(non-XSK) NAPI RX path.  These leaked packets bypass AF_XDP entirely and
reach the kernel TCP stack via VLAN sub-interfaces.  The kernel finds no
socket for the SNAT'd IP addresses and emits TCP RSTs to the server, which
tears down the connection.

### Contributing factors

**TX backpressure halts RX processing** (`afxdp.rs:1842-1849`):

```rust
let tx_backlog = binding.pending_tx_local.len() + binding.pending_tx_prepared.len();
if tx_backlog >= binding.max_pending_tx {
    binding.dbg_backpressure += 1;
    let _ = drain_pending_tx(binding, now_ns, shared_recycles);
    return did_work;  // <-- early exit, no fill ring refill
}
```

When `pending_tx_prepared.len() + pending_tx_local.len() >= max_pending_tx`,
the entire RX loop returns early.  This also skips `drain_pending_fill()`,
starving the fill ring of recycled frames during the exact conditions (high
forwarding load) that consume them fastest.

**Copy mode overhead**: Each redirected packet incurs a `memcpy` from kernel
DMA buffer into UMEM, slowing the RX-to-fill-ring recycle loop versus
zero-copy.

**Single-queue processing**: One worker thread handles one (ifindex, queue_id)
pair; all RX, TX, fill ring management, and session lookups are serialized.

## 3. Current Mitigation: nftables RST Suppression

Since the root cause is kernel-emitted RSTs for SNAT addresses the kernel
doesn't own, the dataplane installs nftables rules to suppress them.

`install_kernel_rst_suppression()` (`afxdp.rs:6499`) creates an
`inet xpf_dp_rst` table with an output chain that drops outgoing TCP RSTs
from all interface-NAT (SNAT) addresses:

```
table inet xpf_dp_rst {
  chain output {
    type filter hook output priority 0; policy accept;
    ip saddr <snat_v4_addr> tcp flags & rst == rst counter drop
    ip6 saddr <snat_v6_addr> tcp flags & rst == rst counter drop
  }
}
```

The rules are:
- Auto-installed when forwarding state is rebuilt from the config snapshot.
- Auto-removed on DP shutdown via `remove_kernel_rst_suppression()` (`afxdp.rs:6603`).

**Validation**: 1m / 100m / 500m / 1g downloads complete at ~107 MB/s through
NAT.  Before the fix, 1g downloads failed 100% of the time.

## 4. Queue And Frame Ownership After Phase 4

Phase 4 of the cleanup plan made the prepared-TX recycle path explicit.

### 4a. Explicit prepared-TX recycle ownership

Prepared TX requests now carry an explicit recycle destination instead of the
older implicit "maybe a slot, maybe a TX frame" model:

```rust
enum PreparedTxRecycle {
    FreeTxFrame,
    FillOnSlot(u32),
}
```

This makes it obvious whether a completed prepared transmit should:

1. return a reserved TX frame to the TX frame pool, or
2. replenish the fill path for a specific ingress slot.

### 4b. Centralized queue merge / drain / restore helpers

Pending local and prepared TX requests are now merged and restored through a
single helper path in `userspace-dp/src/afxdp/tx.rs` instead of open-coded
queue stitching in multiple places.

That cleanup made three things explicit:

1. merge order between local and shared prepared requests
2. when pending requests are restored after backpressure or partial transmit
3. how completion reaping maps offsets back to either TX-frame free or
   fill-ring replenishment

### 4c. What is still left

Phase 4 was about making ownership explicit, not finishing throughput tuning.
The remaining work is now cleaner:

1. measure and optimize sustained forwarding throughput
2. reduce retransmits on the common forward path
3. improve validation so TTL / hop-limit probes do not fail the shell harness
   when they correctly return time-exceeded with a non-zero exit code

## 5. Performance Metrics

| Metric | Value |
|--------|-------|
| Current throughput (1g NAT download) | ~107 MB/s |
| Target | Line rate on mlx5 (10 Gbps+) |
| Copy-mode overhead | 1x `memcpy` per redirected packet |
| Fill ring exhaustion events (pre-fix) | 102M+ (`rx_xsk_buff_alloc_err`) |
| Poll cycle budget | 4 RX batches x 256 packets = 1024 packets/cycle |

**Bottlenecks** (ordered by impact):
1. Common forward-path retransmits and sustained-throughput collapse
2. Queue drain / completion / recycle cost in the mixed copy/zerocopy runtime
3. Single-queue processing (no RSS fan-out)
4. Session table contention (if multi-queue)

**Monitoring**:
- `ethtool -S <iface> | grep xsk` -- driver-level AF_XDP stats (`rx_xsk_buff_alloc_err`, `rx_xsk_packets`, etc.)
- `show chassis cluster data-plane statistics`
- `show chassis cluster data-plane interfaces`
- `dbg_backpressure` counter tracks TX backpressure events per binding

## 6. Debug Instrumentation

**Compile-time feature**: `cargo build --features debug-log`

| Build | Behavior |
|-------|----------|
| Without `debug-log` | Zero-overhead production build. `debug_log!()` compiles to nothing. |
| With `debug-log` | Per-packet TCP flag parsing, RST detection, hex dumps, checksum verification, session dumps, stall detection, ring diagnostics. |

**XDP fallback stats**: The shim maintains per-reason counters in
`userspace_fallback_stats` (array map with `USERSPACE_FALLBACK_REASON_MAX`
entries).  The worker reads and logs these as `DBG w{}: XDP_FALLBACK: ...`.

**Binding debug state**: Each `BindingWorker` tracks live ring state
(`debug_pending_fill_frames`, `debug_free_tx_frames`,
`debug_pending_tx_prepared`, `debug_outstanding_tx`) exposed via the
coordinator's status reporting.
