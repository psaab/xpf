# HA Cluster Tests

## Overview

HA cluster tests validate failover, crash recovery, session sync, fabric forwarding, and VRRP behavior. These require a two-VM cluster (eBPF or userspace) with a test host.

## Prerequisites

```bash
# eBPF cluster
make cluster-deploy                # Build + push to xpf-fw0 + xpf-fw1

# Userspace cluster (on loss remote)
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

`deploy all` already performs a rolling restart. Use
`./test/incus/cluster-setup.sh restart all` only when you are explicitly
testing restart behavior without rebuilding.

After a reboot of the remote `loss` host, run `refresh-vfs` first:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs
```

## Test 1: Basic Failover (`make test-failover`)

**What it tests**: TCP survives reboot of the primary node during active iperf3 traffic.

**Procedure**:
1. Verify fw0 is primary
2. Start iperf3 -P 8 from cluster-lan-host to WAN target
3. Reboot fw0 (SIGTERM + hard reboot)
4. Verify iperf3 continues on fw1 (failover)
5. Wait for fw0 to come back
6. Verify failback completes
7. Check iperf3 final bitrate > threshold

**Pass criteria**: iperf3 completes without error, combined bitrate above minimum.

```bash
make test-failover
```

## Test 2: Crash Recovery (`make test-ha-crash`)

**What it tests**: Daemon crash (SIGKILL), graceful stop, multi-cycle crash recovery.

**Scenarios**:
- Force-stop (SIGKILL) fw0 → verify fw1 takes over
- Daemon-stop (systemctl stop) fw0 → planned shutdown with priority-0 burst
- Multi-cycle: crash fw0, recover, crash fw1, recover

```bash
make test-ha-crash
```

## Test 3: Restart Connectivity (`make test-restart-connectivity`)

**What it tests**: Zero packet loss during daemon restart on the primary.

**Procedure**:
1. Start continuous ping from host to WAN target
2. Restart xpfd on primary (systemctl restart)
3. Count lost pings during restart window
4. Verify loss is within acceptable threshold

```bash
make test-restart-connectivity
```

## Test 4: Stress Failover

**What it tests**: Rapid repeated failover cycles don't break the cluster.

```bash
./test/incus/test-stress-failover.sh
```

## Test 5: Double Failover

**What it tests**: Two consecutive failovers (fw0→fw1→fw0) during active traffic.

```bash
./test/incus/test-double-failover.sh
```

## Test 6: Chained Crash

**What it tests**: Sequential crash of both nodes with recovery between each.

```bash
./test/incus/test-chained-crash.sh
```

## Test 7: Active-Active (Per-RG)

**What it tests**: Different RGs primary on different nodes simultaneously.

```bash
./test/incus/test-active-active.sh
```

## Test 8: Private RG

**What it tests**: Redundancy group with isolated failover (doesn't affect other RGs).

```bash
./test/incus/test-private-rg.sh
```

## Userspace-Specific HA Tests

### Full Validation Suite

```bash
RUNS=3 DURATION=5 PARALLEL=4 \
PREFERRED_ACTIVE_NODE=0 \
PREFERRED_ACTIVE_RGS="1 2" \
scripts/userspace-ha-validation.sh
```

Tests:
- active-node settle and userspace arm
- IPv4/IPv6 reachability to the env-selected targets (`IPERF_TARGET4` / `IPERF_TARGET6`)
- TTL / hop-limit time-exceeded behavior
- `mtr` embedded-ICMP NAT reversal
- `iperf3` collapse detection via JSON metrics
- cold-start / neighbor warmup behavior

### Failover Validation

```bash
TOTAL_CYCLES=3 CYCLE_INTERVAL=10 \
scripts/userspace-ha-failover-validation.sh --duration 90 --parallel 4
```

Tests:
- RG ownership move and userspace arm on the new owner
- pre-failover and post-failover `iperf3` continuity
- external IPv4/IPv6 reachability during steady state and after each failover/failback phase
- immediate target reachability after each phase
- proof that the old owner actually transmitted on the fabric path
- proof that standby WAN egress stayed flat while the stale-owner redirect was active
- bounded session/neighbor/route/policy deltas during each move
- standby helper readiness on the old owner after each move
- zero-interval and retransmit collapse detection
- session pickup on both nodes

Use [userspace-fabric-failover.md](userspace-fabric-failover.md) for the
phase-level acceptance bar, thresholds, and artifact interpretation.

For multi-cycle runs, prefer letting the script pick the duration from the
cycle count. The hardened validator now rejects too-short runs up front instead
of misreporting them as mid-cycle `iperf3` completion failures.

If the lab's public/WAN path is already down before the test starts, isolate
that first. Only then use `CHECK_EXTERNAL_REACHABILITY=0` to keep exercising
the failover dataplane without falsely claiming internet reachability passed.

### Manual stale-owner fabric check

When the user reports "traffic is still showing up on the standby WAN," do not
trust aggregate interface counters or `bwm-ng` alone. Measure fresh deltas
around one RG move and one traffic run.

Example:

```bash
# Put RG1 on node0 so node1 becomes the stale owner for LAN ingress.
incus exec loss:xpf-userspace-fw1 -- \
  bash -lc 'cli -c "request chassis cluster failover redundancy-group 1 node 0"'

# On node1, watch the standby WAN and fabric parent in real time.
incus exec loss:xpf-userspace-fw1 -- \
  bash -lc 'timeout 5 cli -c "monitor interface ge-7-0-2"'
incus exec loss:xpf-userspace-fw1 -- \
  bash -lc 'timeout 5 cli -c "monitor interface ge-7-0-0"'

# Then run the stale-owner load from cluster-userspace-host.
incus exec loss:cluster-userspace-host -- \
  bash -lc "iperf3 -J -c $IPERF_TARGET4 -P 4 -t 5"
```

Interpretation:

- `ge-7-0-0` TX rising with `ge-7-0-2` TX flat means stale-owner redirect is
  working and the traffic is crossing fabric.
- `ge-7-0-2` TX rising on the standby while RG1 is inactive there is a real
  leak or owner-state bug.
- high `Copy TX`, high retransmits, and low bitrate on `ge-7-0-0` indicate a
  fabric performance problem, not a missing redirect.

### Native GRE Validation

```bash
PREFERRED_ACTIVE_NODE=1 \
scripts/userspace-native-gre-validation.sh --deploy --iperf --udp --traceroute --failover --count 3
```

Tests:
- steady GRE ICMP and TCP transit
- GRE `iperf3` continuity
- UDP burst over native GRE
- traceroute / `mtr` style probes over GRE
- failover and failback with the native GRE path
- optional host-origin validation with `GRE_VALIDATE_HOST_PROBES=1`

See [native-gre.md](native-gre.md) for the GRE-specific acceptance bar and
capture workflow.

### Benchmark Placement Discipline

For any HA throughput comparison, pin the full dataplane RG set before drawing
conclusions. Otherwise you can accidentally compare split ownership against
single-owner placement and mislabel the result as a regression.

At minimum, verify:

- RG `0`, `1`, and `2` ownership is the intended node
- the active userspace firewall is the node you expect
- the standby node is healthy and ready before failover tests

## Manual Validation Checklist

After any HA code change, verify:

- [ ] `show chassis cluster status` — all RGs have primary + secondary
- [ ] Fabric forwarding path ready on both nodes
- [ ] VIPs present on primary only
- [ ] Session sync count > 0 after establishing flows
- [ ] Ping `"$IPERF_TARGET4"` / `2001:559:8585:80::200` from host — 0% loss
- [ ] `scripts/userspace-ha-validation.sh` passes with current thresholds
- [ ] `scripts/userspace-ha-failover-validation.sh` shows positive fabric TX delta on the old owner for each RG move
- [ ] Standby WAN TX stays flat during the stale-owner phase when fabric redirect is expected
- [ ] `scripts/userspace-ha-failover-validation.sh` keeps session/neighbor/route/policy deltas within threshold during each RG move
- [ ] `iperf3 -P 8` does not collapse to zero on any stream
- [ ] mtr shows intermediate hops (embedded ICMP NAT reversal)
- [ ] After `systemctl restart xpfd` on primary: connectivity recovers within 40s
- [ ] After failover: connectivity recovers within 500ms
- [ ] If GRE is affected: `scripts/userspace-native-gre-validation.sh --iperf --udp --traceroute --failover` passes
