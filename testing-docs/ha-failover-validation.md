# Historical HA Failover Validation -- Loss Userspace Cluster

Date: 2026-03-24

Status: historical archive. Do not use this file as the active userspace HA
runbook.

This document records the bugs found, fixes applied, and test procedures used
for the March 2026 HA investigation on the isolated userspace AF_XDP cluster
running mlx5 ConnectX SR-IOV VFs. It preserves useful history, but the legacy
eBPF dataplane fallback described here is not an accepted userspace validation
result.

For current userspace HA validation, use:

- [failover-testing.md](failover-testing.md)
- [userspace-fabric-failover.md](userspace-fabric-failover.md)
- `scripts/userspace-ha-validation.sh`
- `scripts/userspace-ha-failover-validation.sh`

Current userspace validation must stay on the userspace dataplane. An
attachment or auto-swap to the legacy `xdp_main_prog` path is historical
fallback behavior only; treat it as a userspace validation failure unless the
test is explicitly scoped as a legacy eBPF regression.

> **#16111 warning:** in-VM `tcpdump` is blind to AF_XDP fast-path flows
> (see [failover-testing.md](failover-testing.md), "Observation points").
> Any capture procedure in this historical archive that runs `tcpdump`
> inside a firewall VM will report `0 packets captured` for fast-path
> transit whether or not the flow traversed the node; do not use it as a
> current failover playbook.

## Current Userspace HA Gate

The active pass criteria are maintained in
[failover-testing.md](failover-testing.md) and
[userspace-fabric-failover.md](userspace-fabric-failover.md). In summary, a
current userspace HA run must show:

- `scripts/userspace-ha-validation.sh` passes steady-state reachability and
  throughput checks before failover testing starts.
- `scripts/userspace-ha-failover-validation.sh` passes RG move and failback
  under established load.
- The active and standby userspace helpers remain armed: userspace forwarding
  is supported, active RGs are enabled, forwarding is armed where expected, and
  ready bindings stay non-zero.
- The XDP userspace shim/helper path remains attached on userspace data
  interfaces; the legacy `xdp_main_prog` fallback is not counted as success.
- Failover artifacts show external IPv4 and IPv6 reachability, no
  zero-throughput collapse, positive old-owner fabric TX deltas when stale-MAC
  traffic is expected, flat standby WAN TX deltas during fabric redirect, and
  bounded session/neighbor/route/policy deltas.

---

## 1. Historical Summary of Fixes Applied

Ten commits, listed in dependency order. Each commit addresses a distinct
failure mode discovered during HA failover testing on the loss cluster.

| Commit | Summary | Files |
|--------|---------|-------|
| `58e7dd86` | Router flag in NA, ctrl enable timeout, new-flow fabric redirect | `garp.go`, `manager.go`, `afxdp.rs`, `lib.rs` |
| `18068903` | Stale BPF session flush on ctrl enable | `manager.go` |
| `00dc648d` | NAPI bootstrap with varying probes (multi-queue coverage) | `manager.go` |
| `8d4bb7ce` | Standalone AF_XDP XSK rebind test proving two bugs | `test/xsk-repro/` |
| `b95a8dd8` | Avoid link DOWN/UP on RETH MAC change | `linksetup.go`, `garp.go` |
| `e83d4d3a` | Historical XSK liveness gate + legacy eBPF fallback | `manager.go` |
| `2e237a7e` | Suppress stable link-local EADDRNOTAVAIL log spam | `reconcile.go` |
| `375be885` | Replace xdpilone with libxdp C bridge | `csrc/xsk_bridge.c`, `xsk_ffi.rs`, `bind.rs`, `Cargo.toml`, `build.rs` |
| `807ae01a` | eBPF fabric redirect re-FIB for split-RG failover | `bpf/xdp/xdp_zone.c` |
| `4ddf371f` | Persist XSK liveness failure across config reconciles | `manager.go` |

### 1.1 `58e7dd86` -- Router flag in NA, ctrl enable timeout, new-flow fabric redirect

Three independent fixes in one commit:

1. **Router flag in unsolicited NA (`pkg/cluster/garp.go`).**
   `buildUnsolicitedNA` set the flags byte to `0x20` (Override=1, Router=0).
   Per RFC 4861 section 7.2.5, a host that receives NA with Router=0 removes
   the source from its Default Router List. After VRRP failover the new
   primary sent NA for each VIP -- the connected host deleted its IPv6
   default route and entered a 24-second blackout until the next RA. Fixed
   by setting flags to `0xA0` (Router=1, Override=1).

2. **Ctrl enable hard timeout reset (`pkg/dataplane/userspace/manager.go`).**
   Every link-cycle rebind reset both `neighborsPrewarmed` and `ctrlEnableAt`.
   RETH MAC programming causes repeated rebinds, so the 15-second hard
   timeout restarted on each rebind and ctrl never enabled. Fixed by
   preserving `ctrlEnableAt` across rebinds (only set once, on first
   prewarm when the field is zero).

3. **New-flow fabric redirect (`userspace-dp/src/afxdp.rs`).**
   On the session-miss path, when the egress RG was inactive (HAInactive),
   the fabric redirect used `debug.from_zone` (fragile, sometimes None)
   with no fallback. Fixed to use `from_zone_arc` directly and added
   `.or_else(|| resolve_fabric_redirect(...))` as plain fabric fallback.
   Also added fabric redirect for non-flow (no L4 ports) packets.

### 1.2 `18068903` -- Stale BPF session flush on ctrl enable

During the ctrl-disabled window the eBPF pipeline creates
`PASS_TO_KERNEL` entries in the `userspace_sessions` BPF map. After ctrl
enables, the XDP shim sees these stale entries and bypasses XSK, routing
matching flows through the eBPF pipeline instead of the userspace helper.
Fixed by iterating and deleting all `userspace_sessions` entries on the
ctrl 0-to-1 transition.

### 1.3 `00dc648d` -- NAPI bootstrap with varying probes

On mlx5 zero-copy, the NIC only posts XSK fill ring WQEs during NAPI
poll. One ICMP probe per interface hit the same RX queue (ICMP RSS hashes
on `src, dst, proto` only). Queues without NAPI triggers had empty fill
rings -- `XDP_REDIRECT` succeeded at the BPF level but the NIC silently
dropped the packet. Fixed by sending 30 UDP probes with varying
destination ports (RSS uses 4-tuple for UDP) plus ICMP probes with
varying echo IDs, giving statistical coverage of all RX queues.

### 1.4 `8d4bb7ce` -- Standalone AF_XDP XSK rebind test

Added `test/xsk-repro/` with both xdpilone (Rust) and libbpf (C) minimal
AF_XDP tests. Each loads its own XDP program, creates XSK sockets,
receives packets, does link DOWN/UP, rebinds, and checks receive. This
standalone test proved two bugs in isolation (see section 3).

### 1.5 `b95a8dd8` -- Avoid link DOWN/UP on RETH MAC change

`programRethMAC` now tries setting the MAC while the link is UP first.
If the driver supports `IFF_LIVE_ADDR_CHANGE` (mlx5 does), no link cycle
occurs and AF_XDP sockets are preserved. Falls back to DOWN/UP only if
the live change fails. When no link cycle occurs, VIP reconcile, AF_XDP
rebind, and RA re-burst are all skipped (not needed).

### 1.6 `e83d4d3a` -- Historical XSK liveness gate + legacy fallback

This was a historical defense-in-depth change from the March 2026 debugging
window, not a current userspace HA success condition. Two changes were made:

1. `ctrl.enabled` is only set to 1 if at least one binding has
   `rx_packets > 0`. Prevents routing transit traffic into a black hole
   when XSK cannot deliver packets.

2. After 30 seconds of XSK bindings being ready but `rx_packets == 0`,
   the manager historically selected `xdp_main_prog` as a legacy fallback
   to replace the XDP shim with the direct legacy eBPF pipeline. That
   historical fallback restored forwarding during this investigation, but an
   active userspace validation run must treat this attachment as failure unless
   it is deliberately testing legacy eBPF regression coverage.

### 1.7 `2e237a7e` -- Suppress stable link-local log spam

The reconcile tick removes stable link-locals from inactive RG
interfaces. When the address does not exist, `netlink.AddrDel` returns
`EADDRNOTAVAIL`. This logged a WARN every 2 seconds per interface.
Added `EADDRNOTAVAIL` to the suppressed-error set (alongside `ENOENT`
and `ESRCH`).

### 1.8 `375be885` -- Replace xdpilone with libxdp C bridge

xdpilone 1.2.1 is proven broken on mlx5 ConnectX SR-IOV VFs (standalone
test: libbpf Phase 1 rx=3, xdpilone Phase 1 rx=0). Replaced with a C
FFI bridge to libxdp's xsk helpers (`csrc/xsk_bridge.c`), which use the
same code path the kernel developers test against. New Rust module
`src/xsk_ffi.rs` provides the same type API surface as xdpilone. All
356 Rust tests pass.

### 1.9 `807ae01a` -- eBPF fabric redirect re-FIB for split-RG failover

When fabric-forwarded packets arrived at the receiving node and
`bpf_fib_lookup` returned `BLACKHOLE` or `NO_NEIGH` (because the initial
lookup used the fabric interface's VRF), packets were unconditionally
dropped. This killed all existing TCP sessions during per-RG failover.

Fixed in `bpf/xdp/xdp_zone.c`: when `META_FLAG_FABRIC_FWD` is set and
a session exists, attempt a re-FIB in the main routing table
(`tbid=254`). If the main-table FIB succeeds, resolve and forward
normally. If it also fails (true dual-inactive), drop with
`GLOBAL_CTR_FABRIC_FWD_DROP`.

### 1.10 `4ddf371f` -- Persist historical XSK liveness failure across config reconciles

The historical XSK liveness swap to `xdp_main_prog` was being overridden by
config reconciles which re-selected `xdp_userspace_prog`. Added
`xskLivenessFailed` flag that persists and prevents `Compile` from switching
back to the broken XDP shim. Also added `delta-rx` check: the liveness gate now
compares current `rx_packets` against a snapshot taken at gate start, so
transient initial packets do not mask a subsequent stall.

---

## 2. Historical Test Environment

### 2.1 Cluster Topology

```
                         Internet / Upstream
                              |
                    172.16.80.0/24 (VLAN 80)
                              |
               mlx0 (mlx5 PF, SR-IOV, 8+ VFs)
                    VF4            VF5
                     |              |
          +----------+---+  +------+---------+
          | xpf-       |  | xpf-         |
          | userspace-   |  | userspace-     |
          | fw0 (node 0) |  | fw1 (node 1)  |
          | pri: 200     |  | pri: 100       |
          +--+--+--+--+--+  +--+--+--+--+---+
             |  |  |  |        |  |  |  |
  fxp0 -----+  |  |  |        +--|----------- fxp0
  em0 ---------+  |  |        +--||---------- em0
  fab0 -----------+  |        |  |+---------- fab0
  ge-0/0/1 ----------+  WAN  +----- ge-7/0/1
  ge-0/0/2 ----------+  LAN  +----- ge-7/0/2
                 |                   |
                 +-------+  +-------+
                         |  |
      incusbr0                (fxp0, DHCP)
      bpu-hb0                 (em0,  10.99.12.0/30)
      bpu-fab0                (fab0, 10.99.13.0/30)
      mlx1 VF (VLAN 3667)    (LAN,  10.0.61.0/24)

          +---------------------+
          | cluster-userspace-  |
          | host                |
          | eth0: 10.0.61.102   |
          +---------------------+
```

### 2.2 Hardware

| Component | Detail |
|-----------|--------|
| WAN NIC | Mellanox ConnectX (mlx5), SR-IOV VFs, PCI `0000:65:00.4` / `0000:65:00.5` |
| LAN NIC | Mellanox ConnectX (mlx5), SR-IOV VFs, PCI `0000:65:05.4` / `0000:65:05.5`, VLAN 3667 |
| Kernel | 6.18 |
| XDP mode | Native (mlx5 driver-mode XDP) |
| AF_XDP mode | Zero-copy (mlx5 driver support) |

### 2.3 Software

| Component | Detail |
|-----------|--------|
| xpfd | Daemon managing BPF pipeline + userspace AF_XDP helper |
| xpf-userspace-dp | Rust AF_XDP packet processor (libxdp C bridge) |
| Config | `docs/ha-cluster-userspace.conf` |
| Env | `test/incus/loss-userspace-cluster.env` |
| Deploy script | `test/incus/cluster-setup.sh` |

### 2.4 WAN Targets

| Target | Address |
|--------|---------|
| IPv4 WAN | `172.16.80.200` |
| IPv6 WAN | `2001:559:8585:80::200` |

---

## 3. Historical Bugs Found and Proven

### 3.1 Router Flag Bug (RFC 4861 section 7.2.5)

**Symptom.** After VRRP failover, IPv6 connectivity from
`cluster-userspace-host` dropped to zero for 24 seconds. New TCP
connections failed with "Network is unreachable". iperf3 showed
0 Gbps during the blackout.

**Root cause.** The unsolicited Neighbor Advertisement sent as the IPv6
analog of GARP had flags byte `0x20` (Override=1, Router=0). RFC 4861
section 7.2.5 says: if a host receives NA from a router with Router=0,
it MUST remove that router from the Default Router List. The host
deleted its IPv6 default route and waited until the next Router
Advertisement (~24 seconds) to re-learn it.

**Proof.** On the host, immediately after failover:
```
$ ip -6 route show default
(empty -- default route removed)
```
After the fix (flags `0xA0`, Router=1 + Override=1):
```
$ ip -6 route show default
default via fe80::bf:72ff:fe02:0102 dev eth0 ...
```
The default route survives failover.

**Fix.** `pkg/cluster/garp.go`: changed NA flags byte from `0x20` to
`0xA0`.

### 3.2 xdpilone Broken on mlx5

**Symptom.** AF_XDP userspace helper reported `rx_packets=0` on all
interfaces. All transit traffic fell through to `XDP_PASS` (kernel
forwarding) at ~129 Mbps with no SNAT.

**Root cause.** xdpilone 1.2.1 cannot receive packets on mlx5 ConnectX
SR-IOV VFs. The standalone test (`test/xsk-repro/`) proved this in
isolation:

| Mode | Library | Initial Bind | After Link DOWN/UP |
|------|---------|-------------|-------------------|
| zero-copy | **libbpf** | **rx=3 PASS** | **rx=0 FAIL** |
| zero-copy | xdpilone | rx=0 FAIL | rx=0 FAIL |
| copy | libbpf | rx=0 FAIL | rx=0 FAIL |
| copy | xdpilone | rx=0 FAIL | rx=0 FAIL |

Same NIC, same kernel, same XDP program -- the only variable is the
XSK socket creation library. xdpilone's internal socket setup sequence
is incompatible with the mlx5 driver.

**Fix.** Commit `375be885`: replaced xdpilone with a C FFI bridge to
libxdp's xsk helpers.

### 3.3 mlx5 Zero-Copy Does Not Survive Link DOWN/UP

**Symptom.** Even with libbpf (working initial bind), after
`ip link set <iface> down && ip link set <iface> up`, XSK receive
stops. The NIC increments `rx_xsk_xdp_redirect` (redirect to XSK
attempted) but `rx_xsk_packets` stays flat (XSK never delivers).
`rx_xsk_congst_umr` (UMR congestion counter) is non-zero on the
affected interface.

**Root cause.** Kernel/driver bug: the mlx5 driver does not properly
reinitialize the XSK zero-copy receive path (UMR WQE posting) when the
interface is brought back UP after DOWN.

**Proof.** Standalone test (`test/xsk-repro/libbpf-xsk-test`):
```
Phase 1 (initial bind):  rx=3  PASS
Phase 2 (after DOWN/UP): rx=0  FAIL
```

NIC counters after Phase 2:
```
$ ethtool -S ge-7-0-1 | grep xsk
rx_xsk_xdp_redirect: 147      # redirect attempted
rx_xsk_packets: 0              # never delivered
rx_xsk_congst_umr: 3           # UMR issue
```

**Historical workaround.** Two-layer defense:
1. `b95a8dd8`: Avoid link DOWN/UP entirely during RETH MAC change
   (live MAC change with `IFF_LIVE_ADDR_CHANGE`).
2. `e83d4d3a` + `4ddf371f`: XSK liveness gate detects rx=0 and performs a
   historical auto-swap to `xdp_main_prog` (legacy eBPF pipeline) as fallback.
   Current userspace HA validation must not count that legacy fallback as a
   pass.

### 3.4 eBPF Fabric Redirect Drops on Split-RG

**Symptom.** After per-RG failover (e.g., RG2/LAN moves to node1 while
RG0/RG1/WAN stays on node0), existing TCP sessions through the eBPF
pipeline died. New connections also failed.

**Root cause.** Fabric-forwarded packets arrived at the receiving node
and `bpf_fib_lookup` was performed using the fabric interface's context.
The fabric interface lives in the default VRF, but the destination route
lives in a data VRF -- FIB returned `BPF_FIB_LKUP_RET_BLACKHOLE`. The
`xdp_zone.c` BLACKHOLE handler unconditionally dropped, even for fabric
packets that just needed to be re-looked-up in the main table.

**Fix.** `807ae01a`: When `META_FLAG_FABRIC_FWD` is set and a session
exists, attempt a re-FIB in the main routing table (`tbid=254`).

### 3.5 XDP Shim Fallback Tail-Call Failure

**Symptom.** When the XDP shim (`xdp_userspace_prog`) determined a
packet should go through the eBPF pipeline instead of XSK, its
`fallback_to_main()` tail-call silently failed (returned without
redirecting). The packet fell through to `XDP_PASS`, meaning the kernel
handled it without SNAT.

**Root cause.** aya-ebpf's `tail_call!` macro does not reliably work in
the XDP shim context. The tail-call instruction is emitted but the
program array lookup fails silently.

**Historical workaround.** The XSK liveness gate (`e83d4d3a` + `4ddf371f`)
detects that XSK is broken and uses the legacy `xdp_main_prog` fallback. This
eliminates the shim entirely and sends traffic through the full legacy eBPF
pipeline (zone, conntrack, policy, NAT, forward) at 15+ Gbps. That behavior is
kept here as history; current userspace HA validation must fail on this legacy
fallback unless the run is explicitly a legacy eBPF regression.

### 3.6 Ctrl Enable Never Fires (Rebind Timeout Reset)

**Symptom.** After deploy, `ctrl.enabled` stayed at 0 indefinitely.
Transit traffic went through `XDP_PASS` (kernel, no SNAT).

**Root cause.** Each RETH MAC programming event triggered a link cycle
which triggered XSK rebind which reset `ctrlEnableAt` back to
`now + 15s`. With multiple RETH interfaces, the rebinds chained and the
15-second window never completed.

**Fix.** `58e7dd86`: `ctrlEnableAt` is set only once (first prewarm,
when the field is zero). Subsequent rebinds do not reset it.

### 3.7 NAPI Queue Starvation on mlx5 Zero-Copy

**Symptom.** Some RX queues showed `rx_packets=0` while others
received traffic. Total throughput was reduced.

**Root cause.** mlx5 zero-copy only posts fill ring WQEs during NAPI
poll. The single ICMP prewarm probe hit one RX queue (ICMP RSS is
3-tuple). Other queues had empty fill rings -- `XDP_REDIRECT` to XSK
succeeded at the BPF level but the NIC silently dropped the packet.

**Fix.** `00dc648d`: Send 30 UDP probes with varying destination ports
(4-tuple RSS) plus ICMP probes with varying echo IDs. Provides
statistical coverage across all RX queues.

### 3.8 Stale Session Entries Poison XDP Shim

**Symptom.** After `ctrl` transitions from 0 to 1, some flows bypassed
XSK and went through the eBPF pipeline.

**Root cause.** During the ctrl-disabled window, the eBPF pipeline
created `PASS_TO_KERNEL` entries in `userspace_sessions`. After ctrl
enabled, the XDP shim found these entries and routed matching flows
through the eBPF path instead of XSK.

**Fix.** `18068903` and `00dc648d`: Flush all `userspace_sessions`
entries on the ctrl 0-to-1 transition.

---

## 4. Historical Test Results

### 4.1 Baseline Throughput (All RGs on Same Node)

Measured from `cluster-userspace-host` through the firewall to
`172.16.80.200` / `2001:559:8585:80::200` with `iperf3 -P 4 -t 10`.

| Protocol | Throughput | Retransmits |
|----------|-----------|-------------|
| IPv4 | 23.5 Gbps | 0 |
| IPv6 | 23.1 Gbps | 0 |

### 4.2 HA Failover During iperf3

Failover scenario: all RGs start on node0, then RG2 (LAN) is manually
failed over to node1 during an active iperf3 session.

**Before fixes (24-second blackout):**

| Time Window | Throughput | Notes |
|------------|-----------|-------|
| 0-8s | 23.1 Gbps | Pre-failover baseline |
| 8-32s | 0 Gbps | Complete blackout |
| 32s+ | Partial recovery | Host re-learns IPv6 route via RA |

- Host lost IPv6 default route (Router flag bug)
- `ctrl.enabled` stuck at 0 (timeout reset bug)
- New connections: "Network is unreachable"

**After fixes (sub-second transition):**

| Time Window | Throughput | Notes |
|------------|-----------|-------|
| 0-8s | 23.1 Gbps | Pre-failover baseline |
| 8-9s | 8.4 Gbps | Transition dip (~1s) |
| 9-25s | 10.0-10.4 Gbps | Split-RG fabric redirect path |

- ZERO seconds at 0 Gbps
- Existing TCP sessions survive failover
- Throughput through fabric redirect: ~10 Gbps (expected: fabric adds
  one extra hop per direction)

### 4.3 Post-Failover Connectivity

| Test | Result |
|------|--------|
| IPv4 ping (5 probes, 2s timeout) | 4-5/5 (cold-start first probe may be lost to ARP) |
| IPv6 ping (5 probes, 2s timeout) | 5/5 |
| IPv4 new TCP (iperf3 short) | 5/5 |
| IPv6 new TCP (iperf3 short) | 5/5 |
| IPv6 default route present | Yes (Router=1 in NA preserves it) |

---

## 5. Current Validation Entry Points

This section replaces the old active-looking procedure that waited for an XSK
liveness failure and then verified the legacy eBPF program. That procedure was
valid only for the historical investigation above.

For current userspace HA validation, run the maintained docs and scripts:

- [failover-testing.md](failover-testing.md) for the end-to-end failover
  runbook and pass criteria.
- [userspace-fabric-failover.md](userspace-fabric-failover.md) for
  stale-owner fabric-path interpretation and artifact review.
- `scripts/userspace-ha-validation.sh` before failover, to prove steady-state
  userspace forwarding.
- `scripts/userspace-ha-failover-validation.sh` for RG move and failback under
  load.

### 5.1 Deploy And Preflight

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

After deploy, do not wait for a legacy fallback swap. Preflight the live
userspace dataplane:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
RUNS=3 DURATION=5 PARALLEL=4 \
PREFERRED_ACTIVE_NODE=0 \
PREFERRED_ACTIVE_RGS="1 2" \
scripts/userspace-ha-validation.sh
```

### 5.2 Verify Userspace Attachment

On userspace data interfaces, the userspace XDP shim/helper path must remain
attached and the helper must be ready. A legacy `xdp_main_prog` attachment on a
userspace data interface is a failure for active userspace validation unless
the run is explicitly a legacy eBPF regression.

```bash
# Node 0 -- example WAN interface
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- \
  ip link show ge-0-0-2 | grep prog"

# Node 1 -- example LAN interface
sg incus-admin -c "incus exec loss:xpf-userspace-fw1 -- \
  ip link show ge-7-0-1 | grep prog"
```

Use CLI state, the script artifacts, and `monitor interface <fabric-parent>` to
confirm:

- userspace forwarding is supported
- active RGs are enabled
- forwarding is armed where expected
- ready bindings are non-zero
- old-owner stale-MAC traffic redirects across fabric instead of egressing the
  standby WAN

### 5.3 Hardened RG Move Under Load

Run the hardened failover validator:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=3 CYCLE_INTERVAL=10 \
scripts/userspace-ha-failover-validation.sh --duration 90 --parallel 4
```

Pass/fail comes from the current script and the current runbooks, not from the
historical manual thresholds in this file. The run must preserve IPv4 and IPv6
reachability, avoid zero-throughput collapse, keep failover deltas within
threshold, prove expected fabric TX on the old owner, and keep standby WAN TX
flat during stale-owner fabric redirect checks.

### 5.4 Standalone XSK Rebind Test

This is the standalone test used to bisect AF_XDP bugs independently
of xpfd. It is useful for driver/library regression investigation, not as the
active HA acceptance gate. Run directly on one of the firewall VMs.

```bash
# SSH into a firewall node
sg incus-admin -c "incus exec loss:xpf-userspace-fw1 -- bash"

# In test/xsk-repro/ (must be pre-built and pushed)

# libbpf zero-copy (reference: PASS on initial bind, FAIL after cycle)
./libbpf-xsk-test ge-7-0-1 0 zerocopy

# libbpf copy mode
./libbpf-xsk-test ge-7-0-1 0 copy

# xdpilone (expected to fail on both phases)
./xsk-rebind-test ge-7-0-1 0 \
  --xsk-map-pin /sys/fs/bpf/xpf/userspace_xsk_map
```

**How to use for bisection.** If a future kernel update or driver change
is suspected to fix or break XSK behavior:

1. Run `libbpf-xsk-test` in zero-copy mode.
2. If Phase 1 (initial bind) fails: library or driver regression.
3. If Phase 1 passes but Phase 2 (after link cycle) fails: the
   mlx5 UMR reinit bug is still present.
4. If both phases pass: the kernel bug is fixed and the
   `IFF_LIVE_ADDR_CHANGE` workaround (`b95a8dd8`) can be removed.

---

## 6. Historical Limitations

These limitations describe the March 2026 investigation. They are not current
userspace HA pass criteria.

### 6.1 Historical XSK Liveness Swap Window

During the historical fallback design, the daemon took 15-45 seconds to detect
that XSK was broken and swap to legacy `xdp_main_prog`. During this window,
traffic went through kernel fallback (`XDP_PASS`) at reduced throughput and
without SNAT. This legacy fallback is no longer an accepted result for active
userspace HA validation. The historical window consisted of:

1. Binding setup + NAPI prewarm: ~5-10s
2. Liveness check period: up to 30s (configurable)
3. Program swap: < 1s

### 6.2 mlx5 Zero-Copy After Link DOWN/UP

This is an upstream kernel/driver bug. The workaround (live MAC change via
`IFF_LIVE_ADDR_CHANGE`) avoids triggering it during normal operation. If a
future event forces a link cycle (e.g., driver reload, PCI reset), active
userspace validation should catch the resulting helper/binding failure. Do not
treat a legacy eBPF fallback as userspace success.

### 6.3 libxdp Dynamic Linking

The xdpilone-to-libxdp migration (`375be885`) links `libxdp.so.1`
dynamically. The target firewall VMs must have libxdp installed. The
deploy script installs it automatically, but manual binary copies must
ensure the library is present.

### 6.4 Split-RG Fabric Throughput

When RGs are split across nodes, traffic traverses the fabric link
(one extra hop per direction). Expected throughput is ~10 Gbps through
fabric, compared to 23+ Gbps with all RGs colocated. This is inherent
to the fabric architecture, not a bug.

### 6.5 aya-ebpf Tail-Call Bug

The XDP shim's `fallback_to_main()` tail-call silently failed in aya-ebpf
during this investigation. The historical workaround replaced the shim
entirely, but that is legacy fallback behavior and not a current userspace HA
success condition.

---

## 7. Diagnostic Commands

### 7.1 XDP Program Attached

Check which XDP program is attached to each data interface. For active
userspace HA validation, the userspace shim/helper path is expected. A legacy
`xdp_main_prog` attachment is historical fallback or legacy-regression evidence,
not userspace success.

```bash
# On firewall VM
ip link show ge-0-0-2 | grep prog
# or
bpftool net list
```

List all loaded XDP programs:

```bash
bpftool prog show | grep -E '(xdp_main|xdp_userspace)'
```

### 7.2 Ctrl Map State

Check whether userspace ctrl is enabled in the BPF map:

```bash
bpftool map dump pinned /sys/fs/bpf/xpf/userspace_ctrl
# Key: 0x00 0x00 0x00 0x00
# Value: enabled (1) or disabled (0) as first byte
```

### 7.3 XSK Binding State

The binding status is maintained in a state file by the daemon:

```bash
cat /var/run/xpf/xsk-status.json 2>/dev/null || \
  journalctl -u xpfd --no-pager | grep -i "xsk\|binding\|liveness"
```

Check the BPF bindings map:

```bash
bpftool map dump pinned /sys/fs/bpf/xpf/userspace_bindings
# Non-zero entries indicate active XSK bindings
# All-zero entries after deploy indicate the XSK bind failure
```

### 7.4 NIC XSK Counters

mlx5 exposes per-interface XSK statistics:

```bash
ethtool -S ge-7-0-1 | grep xsk
# Key counters:
#   rx_xsk_xdp_redirect  — XDP redirected to XSK (BPF side)
#   rx_xsk_packets        — XSK actually delivered to userspace
#   rx_xsk_congst_umr     — UMR congestion (indicates driver bug)
#   rx_xsk_drops          — XSK fill ring empty drops
```

If `rx_xsk_xdp_redirect` increments but `rx_xsk_packets` does not,
the mlx5 UMR reinitialization bug (section 3.3) is active.

### 7.5 Fallback Statistics

Check global counters for fabric redirect and fallback:

```bash
# Via CLI
/usr/local/sbin/cli -c 'show security flow statistics'

# Via bpftool -- global counters map
bpftool map dump pinned /sys/fs/bpf/xpf/global_counters
# Look for:
#   GLOBAL_CTR_FABRIC_FWD       — packets fabric-redirected
#   GLOBAL_CTR_FABRIC_FWD_DROP  — fabric redirect failed (dual-inactive)
#   GLOBAL_CTR_KERNEL_ROUTE     — packets sent to kernel (XDP_PASS)
```

### 7.6 Session Map Entries

Check active sessions, especially for fabric-forwarded flows:

```bash
# Via CLI
/usr/local/sbin/cli -c 'show security flow session'
/usr/local/sbin/cli -c 'show security flow session destination-prefix 172.16.80.200/32'

# Count sessions
/usr/local/sbin/cli -c 'show security flow session summary'
```

### 7.7 Cluster State

```bash
# RG ownership
/usr/local/sbin/cli -c 'show chassis cluster status'

# Heartbeat
/usr/local/sbin/cli -c 'show chassis cluster statistics'

# Interface status
/usr/local/sbin/cli -c 'show chassis cluster interfaces'
```

### 7.8 Journal Logs (Filtered)

```bash
# XSK liveness gate events
journalctl -u xpfd --no-pager | grep -i "liveness\|swap.*xdp\|xsk.*fail"

# Ctrl enable events
journalctl -u xpfd --no-pager | grep -i "ctrl.*enable\|ctrl.*disable"

# VRRP transitions
journalctl -u xpfd --no-pager | grep -i "vrrp.*master\|vrrp.*backup"

# Fabric redirect
journalctl -u xpfd --no-pager | grep -i "fabric"

# NA/GARP
journalctl -u xpfd --no-pager | grep -i "garp\|unsolicited.*na"
```

---

## 8. Standalone XSK Reproduction Test

### 8.1 Purpose

`test/xsk-repro/` contains minimal standalone programs that isolate
AF_XDP behavior from the rest of xpfd. They prove that XSK bugs are
in the library (xdpilone) or kernel driver (mlx5), not in xpf
application code.

### 8.2 Contents

| File | Description |
|------|-------------|
| `libbpf-xsk-test.c` | C program using libbpf xsk helpers directly |
| `xsk-rebind-test.rs` | Rust program using xdpilone |
| `xdp_pass.c` | Minimal XDP program (just returns `XDP_REDIRECT` to XSK map) |
| `Makefile` | Build rules for both tests |

### 8.3 Test Protocol

Each test performs two phases:

1. **Phase 1 (initial bind):** Load XDP program, create UMEM, create
   XSK socket, fill the fill ring, send ICMP probes from outside,
   check `rx_packets` after 3 seconds.

2. **Phase 2 (after link cycle):** Bring interface DOWN, bring UP,
   destroy and recreate XSK socket (re-bind), fill the fill ring,
   send probes again, check `rx_packets` after 3 seconds.

### 8.4 Expected Results by NIC/Driver

| Driver | Zero-Copy Phase 1 | Zero-Copy Phase 2 | Copy Phase 1 | Copy Phase 2 |
|--------|-------------------|-------------------|-------------|-------------|
| mlx5 (ConnectX VF) | PASS (libbpf) | FAIL | FAIL | FAIL |
| i40e (X710 PF) | PASS | PASS | PASS | PASS |
| virtio-net | N/A (no zero-copy) | N/A | PASS | PASS |

### 8.5 Future Use

When a kernel update claims to fix mlx5 XSK zero-copy reinit:

1. Update kernel on a firewall VM.
2. Run `./libbpf-xsk-test ge-7-0-1 0 zerocopy`.
3. If both phases pass, the `IFF_LIVE_ADDR_CHANGE` workaround and XSK
   liveness gate can be made optional.
4. If Phase 2 still fails, the workarounds remain necessary.

---

## 9. Historical Commit Dependency Graph

The fixes have the following logical dependencies (commits higher in
the graph must be applied before commits lower):

```
8d4bb7ce  (standalone test -- proves bugs, no code changes to xpfd)
    |
    v
375be885  (replace xdpilone with libxdp -- fixes Bug 3.2)
    |
    v
b95a8dd8  (avoid link DOWN/UP -- mitigates Bug 3.3)
    |
    v
e83d4d3a  (XSK liveness gate -- defense-in-depth for 3.2+3.3+3.5)
    |
    v
4ddf371f  (persist liveness flag -- prevents config reconcile override)

58e7dd86  (Router flag + ctrl timeout + fabric redirect -- independent)
    |
    v
18068903  (stale session flush -- depends on ctrl timeout fix)
    |
    v
00dc648d  (NAPI bootstrap -- extends session flush, adds UDP probes)

807ae01a  (eBPF fabric re-FIB -- independent, BPF-only)

2e237a7e  (log spam -- independent, cosmetic)
```

---

## 10. Current Userspace Validation Checklist

Use the maintained checklist in [failover-testing.md](failover-testing.md) and
[userspace-fabric-failover.md](userspace-fabric-failover.md) for active runs.
The short checklist below exists only to prevent the historical fallback in
this archive from being mistaken for current success:

- [ ] `scripts/userspace-ha-validation.sh` passes before failover testing.
- [ ] `scripts/userspace-ha-failover-validation.sh` passes RG move and
      failback under load.
- [ ] The userspace shim/helper path remains attached on userspace data
      interfaces; legacy `xdp_main_prog` attachment is historical fallback or
      legacy eBPF regression evidence only.
- [ ] Active RGs show userspace forwarding enabled and ready bindings
      non-zero.
- [ ] Standby helpers stay armed where stale-owner fabric redirect is expected.
- [ ] IPv4 and IPv6 external reachability pass before, during, and after
      failover phases.
- [ ] Throughput has no zero-collapse interval.
- [ ] Old-owner fabric TX deltas are positive when stale-MAC traffic should
      cross fabric.
- [ ] Standby WAN TX deltas stay flat during stale-owner fabric redirect.
- [ ] Session, neighbor, route, and policy deltas stay within the current
      validator thresholds.
- [ ] `show chassis cluster status` shows expected RG ownership after each
      phase.
