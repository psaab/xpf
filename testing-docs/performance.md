# Performance Tests

## Overview

Performance tests measure forwarding throughput, latency, and CPU efficiency. They require dedicated hardware (SR-IOV VFs or PCI passthrough NICs).

## Before You Benchmark

Do not start a perf run on an unknown HA state.

For userspace HA on `loss`:

1. Make sure VF trust/VLAN state survived the last host reboot.
2. Deploy or restart the exact tree you want to measure.
3. Pin the intended RG ownership and wait for the active node to settle.
4. Warm neighbors for the `IPERF_TARGET4` / `IPERF_TARGET6` targets.
5. Only then run throughput or `perf`.

The easiest way to re-establish a clean userspace baseline is:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all

RUNS=1 DURATION=5 PARALLEL=4 \
PREFERRED_ACTIVE_NODE=0 \
PREFERRED_ACTIVE_RGS="1 2" \
scripts/userspace-ha-validation.sh
```

If the remote `loss` host rebooted since the last good run, repair SR-IOV state
first:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs
```

## Test 1: Baseline Throughput

**What it tests**: Maximum sustained forwarding rate through the dataplane.

```bash
# Userspace cluster (mlx5 AF_XDP)
scripts/userspace-perf-compare.sh --duration 10 --parallel 8

# Or manually from cluster-userspace-host (source test/incus/cluster-env.sh
# first; IPERF_TARGET4 is loss 172.16.80.202 today, #18576):
incus exec loss:cluster-userspace-host -- iperf3 -c "$IPERF_TARGET4" -P 8 -t 10
incus exec loss:cluster-userspace-host -- iperf3 -6 -c 2001:559:8585:80::200 -P 8 -t 10
```

`scripts/userspace-perf-compare.sh` writes artifacts under
`/tmp/userspace-perf-compare/`, including:

- `summary.md`
- per-family `iperf3` JSON
- per-family `perf report`
- active-firewall helper state at capture time

**Expected baselines**:

| Metric | eBPF (kernel) | Userspace (XSK) |
|--------|--------------|-----------------|
| IPv4 TCP 8-stream | ~13 Gbps | 20-23 Gbps |
| IPv6 TCP 8-stream | ~13 Gbps | 20-23 Gbps |
| Cold TCP connect | ~1s (TCP retransmit) | ~2ms (buffer-retry) |
| Cold iperf3 IPv4 | N/A | 20+ Gbps |
| Cold iperf3 IPv6 | N/A | 20+ Gbps |

## Test 2: CPU Profiling

**What it tests**: Hot functions and potential regressions.

```bash
scripts/userspace-perf-compare.sh --duration 30 --parallel 8
```

Or manual perf:
```bash
# On the active firewall VM
perf record -F 997 -a -g -- sleep 30
perf report --stdio --no-children --sort dso,symbol
```

**Key symbols to watch**:
- `poll_binding` — main packet processing loop
- `__memmove_evex_unaligned_erms` — cross-NIC payload copy ceiling
- `enqueue_pending_forwards` — direct-path batching/control overhead
- `build_forwarded_frame_into_from_frame` — frame build cost
- `resolve_flow_session_decision` — session-resolution overhead
- kernel XSK / driver helpers (`mlx5e_xsk_*`, `xsk_*`) when debugging zero-copy

## Test 3: Repeated Transit Consistency

**What it tests**: Whether an apparent perf drop is a real dataplane regression
or just an unstable HA/neighbor/bootstrap state.

```bash
scripts/userspace-transit-perf-gate.sh
```

Use this before labeling a result as a throughput regression. It repeats transit
runs and captures helper deltas so you can distinguish:

- collapse with helper-visible faults
- collapse with flat helper counters
- simple lab variance

## Test 4: Flow Cache Hit Rate

**What it tests**: Percentage of established-flow packets served from the flow cache.

```bash
# During iperf3 run, inspect helper counters via:
incus exec loss:xpf-userspace-fw0 -- cli -c "show chassis cluster data-plane statistics"
incus exec loss:xpf-userspace-fw1 -- cli -c "show chassis cluster data-plane statistics"
```

For warm sustained TCP, flow-cache hits should dominate once the sessions are
established.

## Test 5: A/B Comparison

**What it tests**: Throughput difference between two code versions.

```bash
# Save baseline
scripts/userspace-perf-compare.sh --duration 10 --parallel 8
cp /tmp/userspace-perf-compare/summary.md /tmp/baseline-summary.md

# Deploy new code
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all

# Compare
scripts/userspace-perf-compare.sh --duration 10 --parallel 8
diff -u /tmp/baseline-summary.md /tmp/userspace-perf-compare/summary.md
```

**Regression threshold**: > 5% drop in sustained throughput is a regression.

For zero-copy restart/bootstrap issues, compare:

- clean deploy
- daemon restart only
- copy-mode fallback if available

and keep the `perf` artifacts from both states.

## Test 6: Latency Under Load

**What it tests**: Per-packet latency during sustained load.

```bash
# Start background load
incus exec loss:cluster-userspace-host -- iperf3 -c "$IPERF_TARGET4" -P 4 -t 30 &

# Measure latency
incus exec loss:cluster-userspace-host -- ping -c 20 -i 0.1 "$IPERF_TARGET4"
```

**Pass criteria**: P99 latency < 5ms under load (no stalls from lock contention).

## Test 7: Native GRE Throughput

If the change touches native GRE or tunnel handoff, validate GRE throughput
separately from the normal v4/v6 iperf path:

```bash
scripts/userspace-native-gre-validation.sh --iperf --udp --traceroute
```

This catches GRE-specific regressions without mixing them into normal WAN
forwarding measurements. See [native-gre.md](native-gre.md) for the full GRE
test matrix.

## Test 8: Stale-Owner Fabric Throughput

Use this when RG ownership is intentionally split and you need to measure the
old-owner fabric redirect path, not the normal local-owner dataplane.

Example workflow:

```bash
# Make node0 own RG1 so node1 becomes the stale owner for LAN ingress.
incus exec loss:xpf-userspace-fw1 -- \
  bash -lc 'cli -c "request chassis cluster failover redundancy-group 1 node 0"'

# Warm the target, then measure from cluster-userspace-host.
incus exec loss:cluster-userspace-host -- \
  bash -lc "ping -c 5 $IPERF_TARGET4 >/dev/null && iperf3 -J -c $IPERF_TARGET4 -P 4 -t 5"
```

At the same time, inspect the standby old owner:

```bash
incus exec loss:xpf-userspace-fw1 -- \
  bash -lc 'timeout 5 cli -c "monitor interface ge-7-0-0"'
incus exec loss:xpf-userspace-fw1 -- \
  bash -lc 'timeout 5 cli -c "monitor interface ge-7-0-2"'
```

What to look for:

- fabric parent `ge-7-0-0` / `fab1` carries the traffic
- standby WAN `ge-7-0-2` stays flat
- queue spread on the fabric parent is healthy
- retransmits stay bounded

Current lab reality:

- the userspace stale-owner path does redirect correctly across fabric
- the fabric parent is `virtio_net` in copy mode
- so stale-owner throughput is materially lower than the steady local-owner
  `mlx5` dataplane path

Treat this as a separate benchmark class. Do not compare stale-owner fabric
numbers directly to normal v4/v6 steady-state throughput.
