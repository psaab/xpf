# Power Cycle Recovery Bugs (2026-03-27)

Three related bugs found during hard-crash (sysrq-trigger) testing of the HA
cluster on the loss (mlx5 SR-IOV) environment.

---

## Bug 1: Heartbeat Socket Invalidation on VRF Rebind — FIXED

**Severity:** Critical (dual-primary / split-brain on power cycle recovery)
**Affected code:** `pkg/cluster/cluster.go`, `pkg/daemon/daemon.go`
**Status:** Fixed and deployed

### Symptom

After a power cycle of the primary node, both nodes declared themselves primary
— split-brain. The 30-second heartbeat grace period delayed it but could not
prevent it.

### Root Cause

The heartbeat UDP sockets are bound to `vrf-mgmt` via `SO_BINDTODEVICE`. During
DHCP-triggered recompile, `networkd.Apply()` strips VRF bindings from em0, then
step 2.7 of `applyConfig()` re-binds em0 to vrf-mgmt. The existing heartbeat
sockets were created before this disruption and become permanently deaf — the
kernel doesn't retroactively fix socket routing when interfaces move between
VRFs.

### Timeline

```
23:56:46.691  heartbeat started (socket bound to vrf-mgmt)
23:56:46.760  peer heartbeat received (ONE packet — socket works initially)
23:56:48.xxx  DHCP recompile: networkd strips em0 from vrf-mgmt then re-binds
              ... socket dead — no more packets received ...
23:57:16.692  30s grace expires → peer marked lost → SPLIT-BRAIN
```

### Fix

1. Added `hbLocalAddr`, `hbPeerAddr`, `hbVRFDevice` fields to `Manager` struct
   to remember heartbeat connection parameters.

2. Added `RestartHeartbeat()` method — stops old sender/receiver, opens fresh
   sockets with same params. Retries up to 5× with 1s delay if bind fails
   (IP may briefly disappear during VRF transition).

3. After VRF re-bind in `applyConfig()` step 2.7, call
   `d.cluster.RestartHeartbeat()` to replace the dead sockets.

### Verification

```
00:08:56.102  heartbeat started
00:08:56.159  peer heartbeat received (works)
00:09:00.750  restarting heartbeat after VRF rebind
00:09:00.753  heartbeat started (fresh sockets)
              ... NO timeout, NO peer-lost — heartbeat continues ...
```

Power cycle test: node0 crashed, node1 took primary. node0 recovered as
secondary. No split-brain. Heartbeat survived two consecutive VRF rebinds.

### Addendum (#1792, 2026-06): restart-window liveness hardening

`RestartHeartbeat()` itself opened two liveness gaps that were closed as
part of the #1800 §5.6 monotonic-liveness unit:

1. **Peer side — no grace during our restart.** The bind-retry loop can
   keep our UDP heartbeats silent for up to ~5 s, but the peer's
   detection window is 5 × 100 ms. `RestartHeartbeat` now invokes a
   notify hook (wired by the daemon to
   `SessionSync.SendLivenessKeepalive`) before teardown and after each
   failed bind retry. The keepalive refreshes the peer's
   `LastPeerReceiveAge`, which its heartbeat-timeout suppression guard
   (`shouldSuppressPeerHeartbeatTimeout`, 2 s recency window, 5 s
   continuous-suppression cap) consults before electing/fencing. The
   suppression is bounded and self-clearing, so a node that truly dies
   mid-restart still fails over. **Residual gap:** if the sync TCP
   connection is also down or silent for >2 s during a >500 ms restart,
   the peer still declares peer-lost — indistinguishable from real node
   death without a heartbeat wire-protocol change (out of scope). The
   default 5 × 100 ms window is intentionally unchanged: with
   `private-rg-election` compiled on by default, heartbeat detection
   owns promotion latency.

2. **Local side — peer death during restart was never detected.** The
   replacement receiver started with `lastSeen=0`, whose timeout path
   only invokes `handlePeerNeverSeen` (a no-op once `peerEverSeen` is
   set). `RestartHeartbeat` now seeds the new receiver's `lastSeen`
   from the old receiver (CLOCK_MONOTONIC nanos — comparable across an
   in-process restart), so a peer that dies while our sockets are down
   is detected once the post-restart 30 s startup grace expires. The
   grace itself re-arms automatically: `StartHeartbeat` constructs a
   fresh receiver and `start()` resets `startedAt`.

All heartbeat/sync liveness timestamps were also moved off wall-clock
`UnixNano` round-trips to `CLOCK_MONOTONIC` (`cluster.MonotonicNanos`)
so NTP steps / VM pause-resume can no longer fire false peer-loss
(#1792).

### Addendum (#9722, 2026-09): the post-restart grace is no longer 30 s

Item 2 above relied on the replacement receiver re-arming the 30 s cold-boot
grace. That grace also hid a peer that died just after an ordinary commit.
Every apply that rebinds the management VRF calls `RestartHeartbeat`, and for
30 s afterwards the seen-then-lost arm returned before checking staleness.

- A replacement for a receiver that had seen the peer now gets the seed before
  it starts, with the 5 s `heartbeatRestartGrace`.
- A replacement for one that never saw the peer, and every `StartHeartbeat`,
  keep the 30 s floor.

See `pkg/cluster/README.md`, "A heartbeat RESTART is not a cold boot".

The same addendum covers #9751. A `RestartHeartbeat` whose five bind retries
all failed used to leave the heartbeat stopped for good: later restarts saw
"not running", and the apply discarded the result. Now:

- the failed restart records a debt, and the next restart retries it with the
  pre-failure seed;
- a deliberate `StopHeartbeat` clears the debt;
- the apply joins the failure into its networkd error.

See "A failed heartbeat restart is owed, not latched" in the same README.

### Addendum (#4033, 2026-07): heartbeat goroutine-leak / double-fire on comms restart

Two coupled defects survived along the comms-restart path (transport
config change → `stopClusterComms` → `startClusterComms`, and the
`RestartHeartbeat` VRF-rebind path):

1. **`StartHeartbeat` overwrote a running heartbeat without stopping it.**
   It reassigned `m.hbSender` / `m.hbReceiver` and started fresh
   goroutines while any previous sender+receiver were still running —
   their `stopCh` was never closed, so they leaked and kept sending. A
   second `StartHeartbeat` (a comms restart, or the daemon bind-retry
   goroutine racing `RestartHeartbeat`) doubled the on-wire heartbeat
   rate and leaked one goroutine set per restart. `StartHeartbeat` is now
   **idempotent**: it tears down any running heartbeat (`StopHeartbeat` —
   cancel + join) *before* installing the new pair, serialized by a
   dedicated `hbStartMu` so two concurrent starts cannot interleave and
   both install. Exactly one heartbeat goroutine set exists at a time.
   `heartbeatSender.stop()` now also closes its send socket (previously
   only the receiver closed its conn — the sender FD leaked on every
   stop/restart).

2. **The daemon bind-retry loop ignored the comms context.** The
   `startClusterComms` heartbeat goroutine looped `for i:=0;i<30` with a
   plain `time.Sleep(2s)` — it never observed `commsCtx`. On a comms
   restart the old retry goroutine survived `stopClusterComms` (up to
   30×2s = 60s), and could call `StartHeartbeat` *after* teardown,
   installing a heartbeat into a dead comms lifecycle and racing the
   replacement goroutine. The loop is now `startHeartbeatWithRetry(ctx,
   …)`: every iteration checks `ctx.Err()` and every retry sleep uses
   `sleepCtx(ctx, …)`, so a cancelled comms context makes the goroutine
   exit promptly. Combined with (1)'s stop-previous, a comms restart
   leaves exactly one retry goroutine and one heartbeat.

RED-on-revert coverage: `TestStartHeartbeatStopsPreviousHeartbeat`
(cluster — N sequential `StartHeartbeat` calls leave only the last pair
running; all earlier pairs are stopped) and
`TestStartHeartbeatWithRetryExitsMidRetryOnCancel` /
`…ExitsBeforeStartOnCancel` (daemon — the retry loop exits on ctx
cancel instead of spinning the full 60s budget).

---

## Bug 2: XSK Rebind EBUSY After RETH MAC Programming — FIXED

**Severity:** Critical (userspace dataplane permanently dead after boot)
**Affected code:** `pkg/daemon/daemon.go`, `pkg/dataplane/userspace/manager.go`, `pkg/dataplane/userspace/protocol.go`, `userspace-dp/src/main.rs`, `userspace-dp/src/afxdp.rs`
**Status:** Fixed — three-part fix eliminates the EBUSY on cold boot

### Symptom

fw1's userspace dataplane shows `allBindingsBound=false` permanently after
startup. The `xdp_main_prog` (eBPF pipeline) is active instead of
`xdp_userspace_prog`. This was the actual cause of "traffic went to 0" on
failover — fw1 had VIPs but was forwarding through the slower eBPF path.

### Root Cause

During startup, the daemon creates XSK bindings (all 18 succeed), then
immediately triggers a RETH MAC link cycle via `PrepareLinkCycle()` →
`NotifyLinkCycle()`. The rebind attempts to create new XSK sockets on the
same NIC queues, but gets:

```
xsk_socket__create_shared(flags=0x000c): Device or resource busy
```

on every queue (mlx5 zero-copy). The copy-mode fallback also fails with EBUSY.
24 consecutive EBUSY errors across two rebind attempts, zero successful
bindings. The workers are running but have no sockets — dead.

### Why EBUSY

mlx5 zero-copy XSK binds exclusively to a hardware queue. When the old sockets
are closed, the kernel should release the queue's XSK context. But the release
may be asynchronous — the old FD is closed, the worker join completes, but the
kernel hasn't finished tearing down the DMA mapping. The new bind arrives before
the queue is free.

The copy-mode (generic) fallback also fails because mlx5 may still hold the
queue in zero-copy mode during the transition.

### Fix (three parts)

**Part A: Skip spurious NotifyLinkCycle when MAC hasn't changed.**

The 2.6b2 step called `NotifyLinkCycle()` unconditionally for any cluster
config. On restarts where the RETH MAC was already set (from previous boot),
this triggered a completely unnecessary rebind. Fixed by gating on
`needLinkCycleRecovery || rethMACPending`.

**Part B: Defer worker startup when RETH MAC change is imminent.**

Added `DeferWorkers` flag to `ConfigSnapshot`. Before `Compile()`, the daemon
pre-checks whether any RETH MAC change is needed. If yes, sets
`deferWorkers=true` on the snapshot. The Rust helper sees this flag and skips
`reconcile_status_bindings()` — workers are planned but not started. The
first `NotifyLinkCycle()` after MAC programming sends `rebind` which starts
workers for the first time, binding to queues that were never previously held.

**Part C: Increase EBUSY retry window.**

For the DHCP-triggered recompile (which does a second rebind while the first
is still settling), increased retry parameters:
- `BIND_RETRY_DELAY`: 50ms → 250ms
- `BIND_RETRY_ATTEMPTS`: 10 → 20
- `NotifyLinkCycle` delay: 200ms → 1s

Total retry window: 1s + 20×250ms = 6s (was 200ms + 500ms = 700ms).

### Verification

Both fw0 and fw1 now show `allBindingsBound=true` and
`xdpEntryProg=xdp_userspace_prog` after startup. iperf3: 14+ Gbps through
the userspace dataplane.

---

## Bug 3: Fabric Peer Neighbor Missing After Recovery — FIXED

**Severity:** High (recovering node stays "not ready" — can't take primary)
**Affected code:** `pkg/daemon/daemon.go` (fabric probe + refresh)
**Status:** Fixed — IPv6 NDP multicast fallback for fabric peer discovery

### Symptom

After fw0 recovers from a crash, the fabric IPVLAN overlay (fab0) cannot find
the peer's ARP entry (10.99.13.2). All RGs stay "not ready" with reason
`fabric forwarding path not ready`. The fabric refresh retries every 4 seconds
but never succeeds.

### Root Cause

The fabric overlay `fab0` is an IPVLAN child of ge-0-0-0. After a crash
reboot, ge-0-0-0 comes up but the ARP entry for the peer (10.99.13.2) doesn't
exist. The daemon's "proactive neighbor resolution" tries to resolve it but the
peer may not respond to ARP on the IPVLAN overlay (it's a point-to-point
config).

Additionally, the RETH MAC change on ge-0-0-0 may invalidate existing neighbor
entries on the peer side, and the IPVLAN overlay uses the parent's MAC for ARP
which changes with RETH MAC programming.

### Log Evidence

```
00:13:38.406  fabric refresh failed (missing peer neighbor) peer=10.99.13.2
00:13:41.918  fabric refresh failed (missing peer neighbor) — retry
00:13:43.919  fabric refresh failed (missing peer neighbor) — retry
              ... continues every ~4s indefinitely ...
```

### Fix

Added IPv6 NDP multicast as a fallback for fabric peer MAC discovery:

1. **`sendIPv6MulticastProbe()`**: sends ICMPv6 echo to `ff02::1` (all-nodes
   link-local multicast) on the fabric overlay. This is more reliable than
   unicast ARP because multicast always works at L2 regardless of IPVLAN
   state or stale MAC caches.

2. **IPv6 neighbor table fallback in `refreshFabricFwd()`**: if IPv4 ARP
   lookup fails, checks the IPv6 NDP neighbor table on the same overlay
   interface. Finds any non-local link-local neighbor entry — that's the
   peer. Uses its MAC for the `fabric_fwd` BPF map entry.

### Why IPv6 multicast works when ARP fails

After crash recovery with RETH MAC changes:
- IPv4 ARP is unicast to a specific IP — if the peer's ARP table has a stale
  MAC, or the IPVLAN overlay doesn't forward the ARP correctly, resolution
  fails silently
- IPv6 NDP uses multicast solicitation — `ff02::1` reaches ALL nodes on the
  link at L2, bypassing any unicast forwarding issues
- Link-local addresses are always present (kernel auto-configures them)
- The peer's response populates the NDP table with its current MAC

---

## Bug 4: IPv6 Advert Checksum vs Kernel-Selected Source — FIXED (#2644)

**Severity:** High (split-brain on interfaces with multiple link-locals)
**Affected code:** `pkg/vrrp/instance.go` (`sendPacketIPv6`), `pkg/vrrp/manager.go`
(`openIPv6Socket`)
**Status:** Fixed (agy review-044 finding 044-01)

### Symptom

On a VRRP interface carrying more than one IPv6 link-local address, IPv6
advertisements were intermittently dropped by the receiving peer. Both nodes
then declared themselves MASTER — split-brain.

### Root Cause

`sendPacketIPv6` marshals the VRRPv3 packet and computes its pseudo-header
checksum over `srcIP = vi.getLocalIPv6()` (the deterministic lowest link-local).
It then transmitted via `vi.ipv6Conn.WriteTo(data, dst)` on a socket bound to the
wildcard `::` (`net.ListenPacket("ip6:112", "::")`) with no source-address
control message. The kernel performs RFC 6724 source-address selection
*independently* when filling in the outer IPv6 header. With a single link-local
the two always agree; with more than one the kernel could stamp a different
outer source than the checksum was computed over.

The VRRPv3 IPv6 checksum (RFC 5798) is computed over an IPv6 pseudo-header that
includes the source address. The receiver recomputes the checksum using the
*actual outer source* of the received packet. When the outer source differs from
the checksum source, the receiver's checksum mismatches and it silently discards
the advert.

### Fix

Pin the outer source to the checksum source. `sendPacketIPv6` now sends through a
`golang.org/x/net/ipv6.PacketConn` wrapper over the same raw conn, attaching an
`IPV6_PKTINFO` control message:

```go
cm := &ipv6.ControlMessage{Src: srcIP, IfIndex: vi.iface.Index}
```

where `srcIP` is the identical value fed to `pkt.Marshal(true, srcIP, dstIP)` for
the checksum. `IfIndex` scopes the link-local source to the VRRP interface
(link-locals are zone-scoped) and keeps egress deterministic. The wrapper +
send seam (`vi.ipv6Send`) are wired together in `openSocket()`. The
checksum-source == cmsg-source equality is asserted by
`TestSendPacketIPv6PinsSourceViaPktInfo`, which re-parses the captured advert
against `cm.Src` (exactly as the receiver validates) and fails if a kernel-
selected (no-cmsg) source is used.

---

## Combined Impact

When all three bugs fire together during a power cycle:

1. fw0 (primary) crashes
2. fw1 takes all RGs (VRRP MASTER) — but its userspace DP has been dead since
   boot (Bug 2: EBUSY). Traffic goes through eBPF pipeline.
3. fw0 recovers, heartbeat restarts correctly (Bug 1: fixed). But fabric never
   comes up (Bug 3: missing peer neighbor).
4. fw0 stays "not ready" forever. fw1 continues serving traffic via eBPF
   fallback at degraded performance.

### Priority

Bug 2 (XSK EBUSY) is the most impactful — it means the secondary node is never
running the userspace dataplane, so failover always hits the slower eBPF path.
Fixing the double-bind (option 3: skip initial bind before RETH MAC) would
eliminate this entirely.
