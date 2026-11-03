# Userspace Dataplane Tests

## Overview

The userspace AF_XDP dataplane processes transit packets in a Rust helper process using XSK (XDP Socket) zero-copy mode on mlx5 NICs. These tests validate forwarding correctness, performance, cold start behavior, and neighbor resolution.

## Test Environment

- Cluster: `loss:xpf-userspace-fw0` / `loss:xpf-userspace-fw1`
- Host: `loss:cluster-userspace-host`
- Test targets: `IPERF_TARGET4` / `IPERF_TARGET6` from `test/incus/cluster-env.sh` (loss today 172.16.80.202 / 2001:559:8585:80::200, #18576)

Important:

- Source `test/incus/cluster-env.sh` first so the commands below use the
  env-selected targets (`IPERF_TARGET4` / `IPERF_TARGET6`).
- The IPv6 target lives on the external lab host; the IPv4 target is the
  `MOUSE_TARGET_NAME` container (`loss:xpf-mouse-target`). Neither is
  `userspace-wan80-host`. Do not measure v4 `172.16.80.200`: the external
  box also answers it (#18576).
- For a packet capture on the v6 endpoint use the gRPC capture service
  described in `~/README.md` (`capture-client` or `grpcurl`); for the v4
  target, capture inside the container (see
  `.codex/skills/iperf-grpc-tcpdump/`).
- After a reboot of the remote `loss` host, repair VF trust/VLAN state first:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs
```

## Deployment / Restart Discipline

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

`deploy all` already performs the rolling stop/cleanup/push/restart sequence.
Do not manually restart both nodes immediately afterward unless the point of the
test is specifically restart behavior.

## Test 1: Cold Start — New Connection After Restart

**What it tests**: First TCP/ICMP connection to a host with no ARP/NDP entry succeeds within ~2ms.

**Procedure**:
```bash
# Restart daemon
incus exec loss:xpf-userspace-fw0 -- systemctl restart xpfd
sleep 40  # Wait for VRRP election + ctrl enable (15s HA delay)

# Test IPv4
incus exec loss:cluster-userspace-host -- ping -c 2 -W 3 "$IPERF_TARGET4"
# Test IPv6
incus exec loss:cluster-userspace-host -- ping6 -c 2 -W 3 2001:559:8585:80::200
```

**Pass criteria**: Both return at least 1 received packet.

**Automated** (20 restart cycles):
```bash
for i in $(seq 1 20); do
  incus exec loss:xpf-userspace-fw0 -- systemctl restart xpfd
  sleep 40
  v4=$(incus exec loss:cluster-userspace-host -- timeout 5 ping -c 2 -W 3 "$IPERF_TARGET4" 2>&1 | grep -oP '\d+(?= received)')
  v6=$(incus exec loss:cluster-userspace-host -- timeout 5 ping6 -c 2 -W 3 2001:559:8585:80::200 2>&1 | grep -oP '\d+(?= received)')
  echo "[$i] v4=$v4 v6=$v6"
done
```

**Expected**: 20/20 pass.

### Why 40s Wait?

The HA startup sequence: BPF load (~3s) → VRRP election (~7s) → RETH MAC + XSK rebind (~3s) → ctrl enable delay (15s) → RA burst → ready. Total ~28-35s.

## Test 2: Neighbor Resolution After Flush

**What it tests**: Traffic to a host with no ARP/NDP entry is buffered, probed, and retried.

```bash
# Flush firewall's WAN-side neighbors
incus exec loss:xpf-userspace-fw0 -- \
  bash -c 'ip neigh flush dev ge-0-0-2.80; ip -6 neigh flush dev ge-0-0-2.80'

# Test (should succeed within 2ms via buffer-and-retry)
incus exec loss:cluster-userspace-host -- ping -c 1 -W 3 "$IPERF_TARGET4"
incus exec loss:cluster-userspace-host -- ping6 -c 1 -W 3 2001:559:8585:80::200
```

**Pass criteria**: Both succeed. The MissingNeighbor handler triggers an ICMP SOCK_RAW probe, the netlink monitor detects the new neighbor, and the buffered packet is retried.

## Test 3: Warm Forwarding — 0% Loss

**What it tests**: Established flows have zero packet loss and consistent TTL.

```bash
# IPv4: 50 pings at 100ms interval
incus exec loss:cluster-userspace-host -- ping -c 50 -i 0.1 "$IPERF_TARGET4"
# IPv6: 50 pings
incus exec loss:cluster-userspace-host -- ping6 -c 50 -i 0.1 2001:559:8585:80::200
```

**Pass criteria**:
- 0% packet loss (50 transmitted, 50 received)
- All packets TTL=63 (no TTL=62 double-decrement from fabric path)
- Latency < 1ms average

## Test 4: Throughput

**What it tests**: Line-rate forwarding through the XSK dataplane.

```bash
# IPv4 TCP
incus exec loss:cluster-userspace-host -- iperf3 -c "$IPERF_TARGET4" -P 8 -t 10
# IPv6 TCP
incus exec loss:cluster-userspace-host -- iperf3 -c 2001:559:8585:80::200 -P 8 -t 10
```

**Pass criteria**: > 18 Gbps sustained (8 streams, 10s).

**Automated**:
```bash
scripts/userspace-perf-compare.sh --duration 10 --parallel 8
```

Before treating a low number as a regression, verify:

- RG ownership is where you expect it
- the active userspace firewall is settled
- neighbors for both targets are warm
- the post-deploy path is not still in cold-start convergence

## Test 5: Embedded ICMP (mtr/traceroute)

**What it tests**: ICMP TTL Exceeded and Unreachable from intermediate routers are NAT-reversed and forwarded back to the originating host.

```bash
# IPv4
incus exec loss:cluster-userspace-host -- mtr -n --report --report-cycles=10 -4 142.251.32.46
# IPv6
incus exec loss:cluster-userspace-host -- mtr -n --report --report-cycles=10 -6 2607:f8b0:4005:811::200e
```

**Pass criteria**:
- Hops 2+ show real IP addresses (not all `???`)
- Responding hops have < 50% loss (routers rate-limit ICMP — some loss is normal)
- Compare with direct mtr from the host (`loss` machine) — should match hop pattern

## Test 6: IPv6 Router Advertisement

**What it tests**: Host receives IPv6 default route via RA after daemon restart.

```bash
incus exec loss:xpf-userspace-fw0 -- systemctl restart xpfd
sleep 35
incus exec loss:cluster-userspace-host -- ip -6 route show default
```

**Pass criteria**: Default route exists via `fe80::bf72:16:2` (stable link-local).

## Test 7: Flow Cache + Descriptor Rewrite

**What it tests**: The flow cache and `apply_rewrite_descriptor` produce correct frames with valid checksums.

```bash
# Run Rust unit tests
cd userspace-dp && cargo test apply_descriptor
cargo test rewrite_forwarded_frame_in_place
```

**Pass criteria**: All 6 descriptor tests + all rewrite tests pass.

## Test 8: NDP / LocalDelivery

**What it tests**: Host can resolve the firewall's link-local via NDP, and host-bound packets (ping to VIP) are delivered to the kernel.

```bash
# Ping firewall VIP
incus exec loss:cluster-userspace-host -- ping -c 3 10.0.61.1
incus exec loss:cluster-userspace-host -- ping6 -c 3 2001:559:8585:ef00::1
```

**Pass criteria**: All replies received. The first packet goes through the LocalDelivery slow-path reinject; subsequent packets hit the BPF session map directly.

## Test 9: Fabric TTL Correctness

**What it tests**: Packets forwarded across the cluster fabric don't get double TTL decrement.

```bash
# After failover (fw1 was recently primary, some sessions route through fabric)
incus exec loss:cluster-userspace-host -- ping -c 20 -i 0.2 "$IPERF_TARGET4" 2>&1 | grep "ttl="
```

**Pass criteria**: ALL packets have TTL=63 (not 62). No TTL=62 in the output.

## GRE Coverage

Native GRE validation has its own test plan:

- [native-gre.md](native-gre.md)

Keep this document focused on the normal v4/v6 userspace dataplane
path. Use the native GRE doc when the change affects:

- tunnel handoff
- native GRE decap / encap
- GRE failover or failback
- firewall-originated GRE traffic

## Known Limitations

- **XDP shim tail-call**: `fallback_to_main` tail call to the eBPF pipeline fails silently on some aya-ebpf versions. Workaround: `XDP_PASS` to kernel.
- **Zero-copy VLAN demux**: mlx5 `XDP_PASS` in zero-copy mode breaks VLAN demux for ARP/NDP replies. Workaround: ICMP SOCK_RAW probes for neighbor resolution.
- **BPF stack limit**: XDP shim must stay within 512 bytes combined stack. New functions must be inlined or minimize stack usage.
- **ICMP session map**: Each `ping` invocation uses a different ICMP echo ID. The BPF session map entry from the previous ping doesn't match. First packet of a new flow always goes through the full session-miss path.
- **Restart/bootstrap diagnosis**: Do not label a zero-copy issue as an mlx5
  kernel bug until you have first ruled out stale deploy state, stale VF
  programming, neighbor propagation failures, and helper heartbeat stalls.
