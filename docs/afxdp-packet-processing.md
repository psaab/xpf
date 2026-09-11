# AF_XDP Userspace Dataplane Packet Processing

> #1373 note: this is the primary packet-processing path for new dataplane
> development and routine validation. References to the legacy BPF pipeline
> below describe explicit fallback/regression boundaries, not the preferred
> implementation target. The retained userspace shim no longer tail-calls into
> `xdp_main_prog` for degraded helper/XSK states. In degraded states it passes
> only proven local/control traffic to the kernel and drops non-local transit.

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

   **Delete inventory (#6537).** `syncIngressIfaceMapLocked`
   (`pkg/dataplane/userspace/maps_sync.go`) keeps `m.lastIngressIfaces`, the
   record of which rows THIS PROCESS installed in this map; its reap loop
   rescans nothing else. The inventory is therefore written on EVERY exit from
   the sync, not only the all-succeeded one. On an early return — a failed
   `Update` (map full / ENOMEM / EPERM) or a failed stale-row `Delete` — it
   becomes `prior ∪ installed-this-pass`, so a row the aborted pass created is
   still reachable later; on a clean pass it is exactly the new ingress set,
   because every prior row outside that set was successfully deleted. Recording
   it only on the all-succeeded path wrote the debt down exactly when there was
   none: a row installed on a pass that failed partway became permanently
   unreachable, and the shim kept treating a de-configured interface as
   ingress. Same shape as the #5697 retry inventory
   `clearStaleBindingRowsLocked` keeps for stale `userspace_bindings` rows.

   **Restart adoption (#6784).** A daemon restart did NOT clear such a row —
   this section previously said it did, and that was the defect. Every shim map
   here is `PinByName`-pinned under `/sys/fs/bpf/xpf`, so `userspace_ingress_ifaces`
   rows outlive xpfd, while `m.lastIngressIfaces` is an ordinary Manager field
   that starts nil. The first sync after a restart therefore reaped nothing:
   any ifindex that dropped out of the config while xpfd was down — or whose
   interface was deleted and its ifindex later reused by a new tunnel/VLAN —
   stayed in the map, and since this map is the gate every later stage sits
   behind, the shim kept diverting that interface's traffic away from
   `cpumap_or_pass` into the AF_XDP path. Retention is deliberate for the
   SESSION maps (that is how HA continuity survives a restart) but it is merely
   incidental for the classifier maps, and nothing rebuilt an inventory for
   them. `adoptIngressInventoryLocked` now enumerates the pinned map ONCE per
   Manager, before the inventory is read, so the reap starts from a truthful
   set. It is a union with any inventory already held (so a #6537 retry debt is
   never dropped) and it is recorded only after a successful enumeration (so a
   transient scan failure retries rather than latching a partial view); an
   enumeration failure is fatal to the classifier sync, which drives
   `userspace_ctrl` to `Enabled=0`. It adopts only rows the shim ACTS on —
   value != 0 — because the shim reads a 0-valued row exactly as it reads an
   absent one (`map_or(true, |v| *v == 0)`), so such a row diverts no traffic;
   that also keeps adoption correct independent of the map's density rather
   than by assuming a HashMap. The sibling classifier maps
   (`userspace_local_v4`/`_v6`, `userspace_interface_nat_v4`/`_v6`) never had
   this hole — they prune by iterating the MAP — so this makes ingress
   consistent with them rather than adding a new mechanism.

   Adoption runs ONCE per Manager, not per pass: within a live process the
   Manager is the sole writer of this map (the Rust helper never touches it,
   the shim only reads it) and `m.lastIngressIfaces` is the #6537 record of
   what this process installed.
3. A binding must exist in `userspace_bindings` for (ifindex, queue_id) and be
   marked `USERSPACE_BINDING_READY`. `queue_id` is the packet's OWN RX queue,
   read once from the XDP context and never transformed on the way to the
   lookup — AF_XDP delivery is queue-bound, so redirecting to a socket bound to
   any other queue is rejected by `xsk_rcv_check()` and the packet dropped
   (#5173). `userspace_bindings` is a flat array indexed by
   `idx = ifindex * BINDING_QUEUES_PER_IFACE + queue_id`, where
   `BINDING_QUEUES_PER_IFACE == 16` (the fixed per-interface stride, defined in
   `userspace-xdp/src/binding_index.rs` alongside the `binding_slot()` mapping
   itself, and mirrored in `pkg/dataplane` `BindingQueuesPerIface` — NOT in
   `bpf/headers`, which only carries `MAX_INTERFACES`). Because the stride is
   fixed, BOTH sides bound the queue dimension:
   - **Write side.** The control plane
     (`pkg/dataplane/userspace/helper_status_apply.go` for the apply path,
     `maps_sync.go` for the watchdog) fails closed on two dimension
     overflows before writing any slot: a `queue_id >= 16` would alias the
     queue-0 slot of the adjacent ifindex (`ifindex*16 + 16 == (ifindex+1)*16`,
     #4894), and an `ifindex >= MAX_INTERFACES` would overflow the array cap
     (#814). The apply path disables `userspace_ctrl` and the watchdog logs and
     skips.

     It also fails closed on three properties of the ROW ITSELF, which the two
     dimension guards above cannot see because they only constrain the index
     (#7497): a `Slot` at or above the slot-keyed map capacity (see the slot
     axis below — the composed-index guards are checked against a bound 256x
     larger and do not stand in for it); a duplicate `(ifindex, queue)`, where
     the second write would silently overwrite the first and orphan its XSK —
     registered and heartbeating, but unreachable by any redirect, and counted
     nowhere; and one `Slot` claimed by two different coordinates, where both
     redirects succeed and one queue has no socket of its own.

     The slot bound is **not** redundant with the helper's own plan-time
     refusal. They are separate trust boundaries: during a rolling HA upgrade
     the two nodes run different binaries, so a peer helper predating that cap
     can hand this manager an out-of-range slot. It is also a different guard
     from the map-ABI drift check in `validateUserspaceShimSpecWith`, which
     verifies the maps are the size we believe at load — not that a row we are
     about to write can be addressed in them.

     Slot uniqueness is scoped to the primary pass alone, and deliberately so:
     `applyAliasBindingRowsLocked` mirrors each VLAN child onto its parent's
     rows carrying the PARENT's slot, so one slot legitimately appears at
     several indices. A uniqueness check spanning both passes would reject
     every VLAN-aliased config.
   - **Read side (shim).** `binding_slot()` returns no slot at all for a
     `queue_id >= 16`, so the shim takes its binding-missing path — local and
     control traffic passes, transit takes the explicit degraded drop. This is
     the matching read-side bound, and it is required because `rx_queue_index`
     comes from the hardware and nothing else clamps it.

   Out-of-stride queue IDs are never clamped/moduloed on either side: reducing
   the coordinate back into range would still steer to a wrong slot, which is
   the #5173 defect in another form. A NIC exposing more than 16 RX queues
   therefore requires reducing its channel count (`ethtool -L`) or a
   coordinated stride bump.

   **The planner DOES cap the queue count (#7497), and the cap is not a
   mitigation (#9040).** `replan_bindings_from_candidates` binds
   `min(rx, BINDING_QUEUES_PER_IFACE)` per interface. That keeps a wide NIC
   usable on its first 16 queues; it does nothing about the other `Q-16`,
   because RSS keeps hashing across all of them. A packet steered to an unbound
   queue has no binding, so the shim passes local/control traffic to the kernel
   and takes `drop_degraded_transit` on transit — a steady loss of roughly
   `(Q-16)/Q` on that interface while it reads up.

   RSS is reshaped to fit the bound set (`computeWeightVector`, which clamps
   `active` to `min(queues, BindingQueuesPerIface)`) on **every interface that
   exposes a readable RSS indirection table**, not only `mlx5_core` (#9040).
   `pkg/daemon/rss_indirection.go` probes each allowlisted netdev with
   `ethtool -x` and reshapes the ones that answer.

   The clamp was never the gap — `computeWeightVector` has always been
   driver-generic. The gap was one level up: `applyRSSIndirection` matched on
   the driver NAME and skipped everything else, so a virtio-net / i40e / ice /
   bnxt NIC never reached the generic clamp at all.

   It is a probe rather than simply a widened gate because `ethtool -X` support
   varies by driver and this path deliberately swallows its errors (a D3
   regression must not break interface bring-up). A reshape that silently
   succeeds on some drivers and silently fails on others would be the same
   class of defect as the one it fixes, one layer up. The probe identifies the
   unsupported case **before** the write, which is what stops the swallowed
   error from mattering; a NIC with no readable table keeps the queue cap
   warning as its whole remedy.

   Restores are deliberately **not** probe-gated, and the asymmetry is
   intentional: #5250 exists because an unreadable signal silently became "do
   nothing" and left a concentrated table live. A wrongly attempted restore is
   a logged no-op; a wrongly attempted reshape is a silent misconfiguration.
   **A restore fails open, a write fails closed.** For the same reason the kill
   switch now sweeps every allowlisted interface rather than only the mlx5
   ones — the restore set must equal the potential-apply set, or backing out
   would strand a table on exactly the NICs the widened apply path can write.

   There is still no `ethtool -L` anywhere in this tree, so nothing reduces the
   channel count on the box's behalf.

   Since #9040 the cap logs a named warning at bring-up, and the resulting
   drops are exported as
   `xpf_dataplane_degraded_path_total{reason="binding_missing"}`. **The
   operator remedy is still `ethtool -L <iface> combined 16`** (or a coordinated
   stride bump); whether the planner should instead REFUSE such a plan — the
   doctrine its own slot-cap sibling states, *"a partial plan is an
   availability failure indistinguishable from healthy"* — is the open question
   on #9040.

   The Go boundary remains the enforcement point for what gets published.

   **The slot axis is a SEPARATE bound, and is not covered by any of the
   above (#7497).** The composed index `ifindex * 16 + queue` addresses
   `userspace_bindings`, whose capacity is `MAX_INTERFACES *
   BINDING_QUEUES_PER_IFACE` = 1,048,576. But the redirect and the liveness
   check are not keyed by that index — they are keyed by `binding.slot`, a
   field of the binding VALUE:

   ```
   lib.rs  USERSPACE_BINDINGS.get(ifindex * 16 + queue)   1,048,576 entries
   lib.rs  USERSPACE_HEARTBEAT.get(binding.slot)              4,096 entries
   lib.rs  USERSPACE_XSK_MAP.redirect(binding.slot, 0)        4,096 entries
   ```

   `slot` is assigned **densely** by the helper planner — a plain counter over
   the bindings it planned (`replan_bindings_from_candidates`) — so it is not
   derived from ifindex or queue id, and `BINDING_SLOT_MAP_MAX_ENTRIES` (4,096,
   in `binding_index.rs`) is a ceiling on the **total number of bindings**. It
   is 256x smaller than the binding array, so the write-side `#814` guard,
   which checks the composed index against the larger value, does **not** stand
   in for it: a slot that guard admits can still be unaddressable in the two
   slot-keyed maps.

   The planner therefore **refuses the whole plan** when
   `queue_count * interfaces` would exceed `MAX_BINDING_SLOTS`, naming the
   interface count, the queue count and the limit. Two properties of that are
   deliberate. It is checked at **plan time**, not at `register_xsk_slot`,
   because registration runs during bringup after the previous bindings have
   been torn down — failing there takes forwarding down instead of declining to
   change it. And it **refuses** rather than truncating to the first 4,096:
   the surplus RX queues would be left unbound, and an unbound queue does not
   reduce throughput, it takes `drop_degraded_transit` on every transit packet
   while the interface still reads up and most traffic still flows. A refusal
   is loud; a partial plan is an availability failure indistinguishable from a
   healthy one.

   Go pins `BindingSlotMapMaxEntries` against the **compiled** shim in
   `validateUserspaceShimSpecWith`, and the helper's mirror is asserted against
   the shim's own source by a host test that `#[path]`-includes
   `binding_index.rs`. The two checks cover different boundaries: the shim `.o`
   is git-tracked and rebuilt only by `make generate`, so source and object can
   drift independently of each other.
4. The binding's heartbeat (written every 250ms by the worker) must not be
   stale (default 5s timeout).
5. ICMP/ICMPv6 is handled by the userspace dataplane or passed to the kernel
   for local/control-plane delivery; the shim no longer tail-calls through
   `userspace_fallback_progs`.
6. Local-destination traffic (matching `userspace_local_v4`/`userspace_local_v6`) passes to kernel.
7. A session MISS is **not** decided by the shim. It redirects the packet to the
   userspace dataplane, which evaluates policy and either creates a session or
   drops (`lib.rs`: *"Let all session misses through to the userspace dataplane"*).
   This item previously said non-SYN TCP without a live `userspace_sessions`
   entry is **dropped by the shim**; that described the retired eBPF pipeline
   (#6899 / C180-021) and would lead an operator to expect a drop where the
   packet is in fact delivered.

   The session-miss guard now lives in the userspace dataplane, and **the action
   differs by disposition** — which is the part the old wording lost:
   - **Transit** dispositions DROP a bare RST/FIN first packet (#4400), and a
     single `has_syn` gate additionally declines the pure-PSH / null / URG
     residual (#4539, subsuming #2151 and #4487).
   - **Host-inbound `LocalDelivery` does NOT drop.** The same gate declines to
     *cache* a session off a non-SYN first packet, but the packet still reaches
     the local stack through the LocalDelivery reinject chokepoint — deliberately,
     so a peer RST/FIN tearing down a firewall-ORIGINATED flow (BGP-active,
     syslog-TCP/TLS, feed/RPM fetches, DNS-over-TCP), or a connection-refused RST
     for the firewall's own outbound SYN, is not lost. Declining to cache never
     skips policy: a later real SYN to a firewall IP is re-evaluated by the
     `to-zone junos-host` mandatory-teardown gate that runs on every
     LocalDelivery session hit.
8. When helper/XSK state is degraded (`ctrl.enabled=0`, missing/not-ready
   binding, stale heartbeat, redirect failure), only the local/control cases
   above may reach the kernel. Transit drops and increments
   `transit_drop` in `degraded_path_counters`.

Packets that pass all checks get a `UserspaceDpMeta` header prepended via
`bpf_xdp_adjust_meta` and are redirected to the AF_XDP socket with
`bpf_redirect_map(&USERSPACE_XSK_MAP, slot)`.

#### Metadata alignment (#7176 / C179-019)

The shim writes `UserspaceDpMeta` with a plain aligned store; the userspace
consumer reads it back with `ptr::read_unaligned`. That asymmetry is
deliberate and measured, not an oversight:

* `meta_ptr == xdp->data - size_of::<UserspaceDpMeta>()`, and
  `size_of == 96` with `align_of == 8`, so `96 % 8 == 0` and therefore
  `meta_ptr % 8 == xdp->data % 8`. Whether the store is aligned depends
  **only** on the driver's `xdp->data`, which is a kernel property.
* Measured on the shipped target (mlx5_core VF, AF_XDP native, kernel
  7.0.0-rc7+) via a kprobe on `bpf_xdp_adjust_meta`: **5,989,142 samples,
  all `% 8 == 0`**, none misaligned. The histogram was not broken down by
  ingress path and no fabric traffic was deliberately driven, so the
  generic-XDP fabric path is unrepresented or under-represented rather than
  proven clean — it is the one surface where the answer could differ.
  The probe's own total is recorded alongside the histogram deliberately: a
  kprobe that never fired and a pointer that never misaligned produce the
  same empty histogram, so the total is what makes the zero a measurement.
* This records that the invariant **currently holds on this target**, not
  that a plain store is sound in general — `ptr::write` to a misaligned
  pointer is UB whether or not the hardware faults.
* Making it explicit costs real budget: `core::ptr::write_unaligned` lowers
  to a byte-wise copy on the BPF backend, measured at +145 instructions and
  +1,152 bytes of `.xdp`, moving #1864 verifier headroom 19.86% -> 18.73%
  against the 15.0% floor. That delta is attributable because a no-change
  rebuild of the object is byte-identical (`f576dfef…`) — the control was
  established before the comparison. Take that cost if the invariant breaks.
* A runtime alignment check is **not implementable**: the verifier rejects
  it with `R1 bitwise operator &= on pointer prohibited`, so a BPF program
  cannot observe a packet pointer's alignment at all.

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

The incident record: TCP RSTs toward the server tore down the connection.
That is consistent with the kernel stack seeing packets for SNAT'd addresses
it has no socket for. **How those packets reached the kernel was not
established.**

An earlier version of this section named the mechanism as mlx5 handing RX to
the regular NAPI path when the fill ring is empty (#9695). Upstream v6.18 mlx5e
has no such path:
- `en/rx_res.c` points RSS at the XSK RQ while XSK is enabled.
- `en/xsk/rx.c` counts `rx_xsk_buff_alloc_err` and posts fewer WQEs.

`tx/rings.rs` likewise records the driver dropping. The known shim paths to the
kernel are the non-IP `XDP_PASS` arm and the cpumap fallback; see
`userspace-dp/src/afxdp/umem/README.md`. A vendor kernel or VF firmware could
behave differently, and that was not measured.

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

### 2a. Bringup fill-ring prime: partial-insert recovery (#2374)

At socket bringup the worker constructor pops every non-reserved UMEM frame
into `initial_fill_frames` and primes the RX fill ring with all of them via
`prime_fill_ring_offsets()` (`userspace-dp/src/afxdp/bind.rs`). Two failure
modes are handled:

- **Total failure** (`inserted == 0` on a non-empty prime): fatal. The socket
  would run with no RX descriptors, so the bind fails closed
  (`fill_prime_is_total_failure`).
- **Partial insert** (`0 < inserted < N`, e.g. a transiently-full ring during
  rebind / shared-UMEM group churn): the prime first retries the un-inserted
  suffix across the NAPI-trigger loop (each `recvmsg`/`poll`/`sendto` lets the
  kernel consume fill entries and free ring slots). Any suffix the ring still
  has not accepted is **returned** (`defer_uninserted_fill_suffix`) and threaded
  back through `open_binding_worker_rings` into the worker's
  `pending_fill_frames` queue. The steady-state `drain_pending_fill()` loop then
  retries exactly those offsets.

Before #2374 the prime errored only on `inserted == 0` and silently accepted a
partial insert: the `(N - inserted)` un-inserted frames were dropped from every
local pool (`pending_fill_frames` started empty), permanently shrinking RX
capacity and starving the fill ring. The recovery mirrors the steady-state
suffix recovery in `tx::rings::drain_pending_fill` (which already pushes a
partial-insert suffix back onto `pending_fill_frames`) so bringup and the
running loop handle a short fill-ring insert identically.

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

**XDP degraded path counters**: The shim maintains per-reason counters for
retained-shim degraded actions. Go exposes them in status JSON as
`degraded_path_counters`. The pinned BPF map remains
`userspace_fallback_stats` as an internal mixed-version compatibility
exception. The map is a **per-CPU** `u64` array (`#4113`): native XDP runs
one program instance per RX queue on distinct CPUs concurrently, and
`incr_fallback_stat` does a non-atomic load/add/store; a shared array would
lose increments when two CPUs bump the same reason in the same window. Per-CPU
storage makes each increment CPU-local; the Go and helper readers
(`readDegradedPathStatsLocked`, `read_degraded_path_stats`) sum across CPUs.

**Trace map insert is trace-flag gated (`#4113`)**: `record_trace` writes the
`userspace_trace` BPF map (a `bpf_ktime_get_ns` read plus an avalanche key
compute plus a `bpf_map_update_elem`) **only** when the control flag
`USERSPACE_CTRL_FLAG_TRACE` is set. Earlier code force-inserted for the
`EARLY_FILTER` / `BINDING_MISSING` stages even with tracing disabled, which was
reachable by unauthenticated traffic aimed at well-known multicast/broadcast
groups (`should_fallback_early`) or during a transient config-reload unbind —
an attacker-influenceable per-packet map-update on the native-XDP ingress core.
Visibility for those stages is preserved by the per-CPU degraded-path counter,
which the call sites bump independently of the trace insert.

**Binding debug state**: Each `BindingWorker` tracks live ring state
(`debug_pending_fill_frames`, `debug_free_tx_frames`,
`debug_pending_tx_prepared`, `debug_outstanding_tx`) exposed via the
coordinator's status reporting.
