# HA Failover During iperf3 — Test Plan

## Purpose

Validate that TCP throughput survives a per-RG failover mid-stream and
that new connections succeed immediately after failover completes.

This test exercises:
- VRRP transition (VIP migration, GARP/NA burst)
- Stable link-local handoff (IPv6 router identity)
- Session continuity across fabric redirect
- New connection establishment on the new primary

## Test Targets

- IPv4: `IPERF_TARGET4` from `test/incus/cluster-env.sh` (loss today
  `172.16.80.202`, #18576; WAN target on ge-0-0-2.80 / VLAN 80)
- IPv6: `2001:559:8585:80::200` (external lab host on the same VLAN)
- Host: `cluster-userspace-host` (LAN, 10.0.61.102)

## Prerequisites

- Both `xpf-userspace-fw0` and `xpf-userspace-fw1` running with latest code
- Cluster healthy: `show chassis cluster status` shows primary + secondary for all RGs
- Takeover ready: yes on both nodes
- Warm traffic: `ping -c 3 "$IPERF_TARGET4" && ping6 -c 3 2001:559:8585:80::200` passes

## Test A: IPv6 iperf3 + RG2 failover

### Step 1 — Start long iperf3 from the host

```bash
# On cluster-userspace-host:
iperf3 -c 2001:559:8585:80::200 -t 60 -P 8
```

Wait ~10s to confirm sustained throughput (should be 20+ Gbps).

### Step 2 — Failover RG2 (LAN) to the other node

```bash
# On the current primary (check with 'show chassis cluster status'):
# If node0 is primary:
request chassis cluster failover redundancy-group 2 node 1
# If node1 is primary:
request chassis cluster failover redundancy-group 2 node 0
```

### Step 3 — Observe iperf3

**Current expected behavior (known bug):**
- iperf3 throughput drops to 0 Gbps within seconds
- After Ctrl-C, new `iperf3 -c 2001:559:8585:80::200` fails with
  "Network is unreachable"

**Target behavior (after fix):**
- Brief throughput dip (< 2s) during VRRP transition
- Recovery to full throughput via fabric redirect or new-primary path
- New connections succeed immediately after failover

### Step 4 — Verify new connection

```bash
# After Ctrl-C of the stalled iperf3:
ping6 -c 3 2001:559:8585:80::200
iperf3 -c 2001:559:8585:80::200 -t 10 -P 8
```

**Pass criteria:**
- ping6 succeeds (0% loss)
- iperf3 connects and shows > 10 Gbps

## Test B: IPv4 iperf3 + RG1 failover

### Step 1 — Start long iperf3

```bash
iperf3 -c "$IPERF_TARGET4" -t 60 -P 8
```

### Step 2 — Failover RG1 (WAN) to the other node

```bash
# If node0 is primary for RG1:
request chassis cluster failover redundancy-group 1 node 1
# If node1 is primary:
request chassis cluster failover redundancy-group 1 node 0
```

### Step 3 — Observe + reconnect

Same criteria as Test A but for IPv4.

**Pass criteria:**
- Brief dip during transition, then recovery
- New `iperf3 -c "$IPERF_TARGET4" -t 10 -P 8` connects immediately

## Test C: Repeated failover stress

Run Tests A and B back-to-back for 5 cycles:

```bash
for i in $(seq 1 5); do
  echo "=== Cycle $i ==="
  # Start iperf3 in background
  timeout 20 iperf3 -c "$IPERF_TARGET4" -t 15 -P 8 &
  sleep 5
  # Failover RG1
  echo "request chassis cluster failover redundancy-group 1 node 1" | cli
  sleep 10
  wait
  # Failback
  echo "request chassis cluster failover redundancy-group 1 node 0" | cli
  sleep 5
done
```

**Pass criteria:**
- No cycle shows 0 Gbps for > 5 seconds
- All cycles complete without "unable to connect" errors

## Root Causes Being Tested

1. **Stable link-local NDP race** — after RG2 failover, the new primary
   must have `fe80::bf72:CC:RR` and the old primary must NOT. If both
   have it, hosts cache the wrong MAC → "Network is unreachable."

2. **Session continuity via fabric** — existing TCP sessions on the old
   primary should be fabric-redirected to the new primary. Requires
   dynamic fabric state sync (`SyncFabricState` / `shared_fabrics`).

3. **Neighbor table persistence** — the new primary's userspace helper
   must have neighbor entries for the WAN targets. The additive neighbor
   update model (`neighbor_replace=false`) must not wipe learned entries.

4. **GARP/NA burst timing** — the new primary must send GARP (IPv4) and
   unsolicited NA (IPv6) before hosts time out their ARP/NDP caches.

## Automated Version

```bash
# From the build host:
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  scripts/userspace-ha-failover-validation.sh \
  --duration 60 --parallel 8
```
