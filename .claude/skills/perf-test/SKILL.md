---
name: perf-test
description: Run IPv4/IPv6 throughput and CPU profiling on bpfrx cluster or standalone VM using iperf3 + perf record.
user-invocable: true
---

# Performance Testing Skill

Run throughput benchmarks and CPU profiling on the bpfrx firewall.

## Host isolation (2026-10-26)

Class **V** (VM/cluster) skill: ALL measurement runs inside Incus
VMs under the cluster lock. Never run iperf/perf, deploy scripts,
or `apt`/`systemctl` directly on the workstation host. If the
target is not provably a VM (`incus list` instance), STOP.
Workstation-side work is limited to building the DEB and reading
results. Kernel/perf cells needing the host kernel belong to the
VM leg, not the workstation.
Traffic flows THROUGH the firewall (from LAN host to WAN) to exercise the full XDP/TC pipeline.

## Arguments

`/perf-test` accepts an optional argument: `ipv4`, `ipv6`, `compare`, `profile`, or `all` (default: `compare`).

- `/perf-test ipv4` — IPv4 throughput only
- `/perf-test ipv6` — IPv6 throughput only
- `/perf-test compare` — IPv4 vs IPv6 side-by-side (default)
- `/perf-test profile` — CPU profiling with perf record
- `/perf-test all` — Throughput compare + CPU profiling

## Environment Detection

Detect which environment is available. Prefer the loss cluster (Mellanox native XDP, 25G) over the local cluster (virtio generic XDP, 10G) over standalone VM.

```bash
# Check the loss userspace cluster first (remote Incus host). Its refs and
# targets come from test/incus/loss-userspace-cluster.env through
# cluster-env.sh: v4 172.16.80.202 (#18576: .200 is also answered by the
# external v6 box), v6 2001:559:8585:80::200, on the reth0.80 fast path.
# Never 172.16.100.x: that is a different uplink capped at ~9-10 Gb/s (#1578).
if incus info loss:xpf-userspace-fw0 2>/dev/null | grep -q RUNNING; then
    source test/incus/cluster-env.sh
    ENV="loss-cluster"
    LAN_HOST="$CLUSTER_LAN_HOST"
    IPV4_TARGET="$IPERF_TARGET4"
    IPV6_TARGET="$IPERF_TARGET6"
# Check local cluster
elif incus info bpfrx-fw0 2>/dev/null | grep -q RUNNING; then
    ENV="local-cluster"
    FW0="bpfrx-fw0"
    FW1="bpfrx-fw1"
    LAN_HOST="cluster-lan-host"
    IPV4_TARGET="172.16.100.200"
    IPV6_TARGET="2001:559:8585:100::200"
# Standalone
elif incus info bpfrx-fw 2>/dev/null | grep -q RUNNING; then
    ENV="standalone"
    FW0="bpfrx-fw"
    LAN_HOST=""  # traffic originates from fw itself
    IPV4_TARGET="66.220.2.74"
    IPV6_TARGET=""  # standalone has no IPv6 WAN target
fi
```

All `incus` commands need the `sg incus-admin -c "..."` wrapper if permission errors occur.

## Throughput Tests

### iperf3 Parameters

| Parameter | Throughput test | Quick validation |
|-----------|----------------|------------------|
| Streams | `-P 4` | `-P 1` |
| Duration | `-t 10` | `-t 3` |
| IPv6 flag | `-6` for IPv6 | `-6` for IPv6 |
| Timeout | none | `timeout 8` wrapper |

### IPv4 Throughput

```bash
# Cluster: traffic from LAN host THROUGH firewall to WAN iperf3 server
incus exec $LAN_HOST -- iperf3 -c $IPV4_TARGET -P 4 -t 10

# Standalone: traffic from firewall to external server
incus exec $FW0 -- iperf3 -c 66.220.2.74 -P 4 -t 10
```

### IPv6 Throughput

```bash
# Cluster only (standalone has no IPv6 WAN target)
incus exec $LAN_HOST -- iperf3 -6 -c $IPV6_TARGET -P 4 -t 10
```

### Compare Mode (default)

Run IPv4 then IPv6 back-to-back, extract sender throughput from each:

```bash
# IPv4
IPV4_RESULT=$(incus exec $LAN_HOST -- iperf3 -c $IPV4_TARGET -P 4 -t 10 2>&1)
IPV4_BW=$(echo "$IPV4_RESULT" | grep '\[SUM\].*sender' | awk '{print $(NF-2), $(NF-1)}')

# IPv6
IPV6_RESULT=$(incus exec $LAN_HOST -- iperf3 -6 -c $IPV6_TARGET -P 4 -t 10 2>&1)
IPV6_BW=$(echo "$IPV6_RESULT" | grep '\[SUM\].*sender' | awk '{print $(NF-2), $(NF-1)}')
```

Present results as a table:

```
| Protocol | Throughput | Retransmits |
|----------|-----------|-------------|
| IPv4     | XX.X Gbps | NNN         |
| IPv6     | XX.X Gbps | NNN         |
| Gap      | XX%       |             |
```

### Expected Baselines

| Environment | IPv4 | IPv6 | Notes |
|-------------|------|------|-------|
| Loss cluster (mlx5 native XDP) | 22+ Gbps | 19+ Gbps | 25G Mellanox ConnectX-5 |
| Local cluster (virtio generic) | 8-9 Gbps | 7-8 Gbps | 10G virtio + iavf VF |
| Standalone (i40e PF passthrough) | 15+ Gbps | N/A | No IPv6 WAN target |

## CPU Profiling

**IMPORTANT:** Traffic must flow THROUGH the firewall, not originate from it.
Run iperf3 from the LAN host, then record perf on the active firewall.

### Step 1: Start traffic (background)

```bash
# IPv4
incus exec $LAN_HOST -- bash -c 'nohup iperf3 -t 60 -c $IPV4_TARGET -P 4 > /tmp/iperf3.out 2>&1 &'

# or IPv6
incus exec $LAN_HOST -- bash -c 'nohup iperf3 -6 -t 60 -c $IPV6_TARGET -P 4 > /tmp/iperf3.out 2>&1 &'
```

### Step 2: Record profile (20s at 997 Hz)

```bash
incus exec $FW0 -- bash -c 'perf record -a -g --freq=997 -o /tmp/perf.data -- sleep 20 2>&1'
```

### Step 3: View report

```bash
incus exec $FW0 -- bash -c 'perf report --no-children --sort=symbol --stdio -i /tmp/perf.data 2>/dev/null | head -60'
```

### Step 4: Pull iperf3 results

```bash
incus exec $LAN_HOST -- cat /tmp/iperf3.out
```

### Step 5: Kill background iperf3

```bash
incus exec $LAN_HOST -- pkill -f iperf3 || true
```

### What to look for in the profile

Key BPF symbols and their expected CPU%:

| Symbol | Healthy range | Red flag | Meaning |
|--------|---------------|----------|---------|
| `xdp_main_prog` | 9-14% | >20% | L2/L3/L4 parsing overhead |
| `xdp_zone_prog` | 7-10% | >15% | Zone lookup + conntrack + flow cache |
| `xdp_forward_prog` | 5-7% | >12% | FIB lookup + redirect |
| `xdp_nat_prog` | 2-5% | >8% | NAT rewrite (IPv6 costs 2x IPv4) |
| `htab_map_hash` | 5-8% | >12% | Session key hashing (40B v6 vs 16B v4) |
| `read_tsc` | 2-4% | >6% | `bpf_ktime_get_coarse_ns()` timestamps |
| `__htab_map_lookup_and_delete_batch` | 4-6% | >20% | Session GC (was 85% before optimization) |
| `bpf_printk` | 0% | >1% | MUST be 0 in production (55% CPU penalty) |

### IPv6 vs IPv4 profile delta

The main IPv6 penalties vs IPv4:
- `htab_map_hash`: +2-3% (40B session key vs 16B)
- `xdp_main_prog`: +2-3% (40B IPv6 header vs 20B IPv4)
- `xdp_nat_prog`: +1-2% (128-bit address rewrite vs 32-bit)
- `lookup_nulls_elem_raw`: +1% (longer memcmp in hash bucket walk)

## Full Compare+Profile Run

For `/perf-test all`, run in this order:

1. IPv4 throughput (iperf3 -P4 -t10)
2. IPv6 throughput (iperf3 -6 -P4 -t10)
3. Print throughput comparison table
4. IPv4 perf profile (iperf3 -P4 -t60 background + perf record 20s)
5. IPv6 perf profile (iperf3 -6 -P4 -t60 background + perf record 20s)
6. Print profile comparison (top 15 symbols side-by-side)
7. Kill all background iperf3

## Historical Results

| Date | IPv4 | IPv6 | Gap | Build |
|------|------|------|-----|-------|
| Pre-#169 | 19.9 Gbps | 19.3 Gbps | 3% | Baseline |
| Post-#169 flow cache | 19.6 Gbps | 18.5 Gbps | 6% | Per-CPU IPv6 flow cache |
| Post-#165/#170 | 22.2 Gbps | 21.9 Gbps | 1.4% | Parse fast path + deferred csum |
| Post-#171/#172/#173 | 22.3 Gbps | 19.3 Gbps | 13.5% | Screen bypass + coarse time + adaptive GC |

## Notes

- Throughput varies ±15% between runs due to iperf3 scheduling, NAPI budget, and ksoftirqd affinity
- Profile percentages are more stable than absolute throughput numbers
- DNS may not resolve on cluster nodes — always use IP addresses directly
- `casper.sf.saab.org` = `66.220.2.74`
- For loss cluster: prefix instance names with `loss:` (e.g., `loss:xpf-userspace-fw0`); `cluster-env.sh` already does this for `$FW0`/`$FW1`/`$CLUSTER_LAN_HOST`
