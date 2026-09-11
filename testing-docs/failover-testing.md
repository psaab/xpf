# Failover Testing

This document is the operational reference for HA failover testing only.
It covers the cluster preflight, the supported failover scenarios, the
current scripts, the manual commands, the required artifacts, and the pass
criteria.

Use this document when the goal is one of:

- proving that RG ownership moves cleanly
- proving that flows survive a failover or recover quickly
- proving that a crashed node fails over to the peer
- proving that a rebooted node can rejoin without killing traffic
- proving that split-RG ownership still behaves correctly

For userspace-specific fabric-path interpretation, also use
[userspace-fabric-failover.md](userspace-fabric-failover.md). For broader HA
cluster context, use [ha-cluster.md](ha-cluster.md).

## Scope

This doc covers three failover test families:

1. Userspace HA RG-move testing on the `loss-userspace-cluster`
2. The Makefile HA smoke gates (`make test-failover`, `make test-ha-crash` and the
   specialised smokes), which run on the loss userspace cluster by default
3. Manual scenario testing when the scripted harness is not enough

It does not cover:

- standalone single-VM forwarding tests
- generic throughput benchmarking without an HA event
- native GRE specifics beyond failover invocation

## Test Environments

### Userspace HA cluster

- Env file: `test/incus/loss-userspace-cluster.env`
- Firewalls:
  - `xpf-userspace-fw0`
  - `xpf-userspace-fw1`
- Host:
  - `cluster-userspace-host`
- Main targets:
  - IPv4: `172.16.80.200`
  - IPv6: `2001:559:8585:80::200`

### Legacy eBPF HA cluster

- Firewalls:
  - `xpf-fw0`
  - `xpf-fw1`
- Host:
  - `cluster-lan-host`

## Tools And Scripts

### HA gates (the Makefile smokes)

These are the gates. `docs/engineering-style.md` requires `make test-failover`
plus `make test-ha-crash` for any HA, VRRP, session-sync or fabric change.

Run them through `make`, not by script path: the targets take the shared
cluster lock (#1875) and record a ledger row (`docs/harness-ledger.md`). They
run on the loss userspace cluster by default; `CLUSTER_ENV=` selects the local
legacy cluster for regression runs.

- `make test-failover` (`test/incus/test-failover.sh`)
  - reboot/failback survival
- `make test-ha-crash` (`test/incus/test-ha-crash.sh`)
  - force-stop, daemon stop, and crash cycles
- `make test-double-failover`, `make test-stress-failover`,
  `make test-chained-crash`
  - specialised stress smokes

### Diagnostic walkthroughs (not gates)

`test/incus/HARNESSES.unreached` declares both of these DIAGNOSTIC and
superseded as gates by the Makefile smokes above. Use them to investigate a
failure or to walk a scenario by hand. A green walkthrough is not an HA pass.

- `scripts/userspace-ha-failover-validation.sh`
  - hardened RG move validation under load
- `scripts/userspace-ha-validation.sh`
  - broader userspace health suite
  - run before blaming failover if steady-state is already broken

## Preflight

Do not start failover testing until all of these are true.

### Cluster health

On each firewall:

```bash
cli -c "show chassis cluster status"
cli -c "show chassis cluster data-plane statistics"
```

Required:

- every tested RG has one primary and one secondary
- no dual-active state
- `Takeover ready: yes` on both nodes unless the specific test is validating a
  readiness failure
- on userspace:
  - `Forwarding supported: true`
  - `Enabled: true` on the active node for the tested RG
  - ready bindings are non-zero

### Target reachability

From the test host:

```bash
ping -c 3 172.16.80.200
ping6 -c 3 2001:559:8585:80::200
```

If these fail before the failover event, stop and isolate steady-state first.

### Local firewall connectivity

From the primary firewall itself, verify that locally-originated traffic works
across all protocols. This validates two things:

1. The XDP shim passes ICMP echo replies for interface-NAT addresses to the
   kernel (`is_icmp_to_interface_nat_local` in `userspace-xdp/src/lib.rs`).
2. The slow-path TUN (`xpf-usp0`) has `rp_filter=0` so the kernel accepts
   TCP/UDP replies whose reverse route points at the real egress interface, not
   the TUN. `networkctl reload` resets this sysctl; the Go daemon must re-apply
   it after every reload (`restoreSlowPathRPFilter` in `pkg/networkd/networkd.go`).

```bash
# On the primary node (whichever owns reth0).
# Use any known-reachable external IP; these are examples for labs with
# Internet egress. In isolated environments, substitute a routable target.

# ICMP — passes through XDP shim fast-path
ping -c 3 1.1.1.1
ping6 -c 3 2001:4860:4860::8888

# TCP — passes through userspace helper → slow-path TUN → kernel
timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/80; echo -e "GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n" >&3; head -1 <&3; exec 3>&-'
```

If ICMP fails, the XDP shim is not recognizing echo replies for interface-NAT
addresses. If TCP fails but ICMP works, check `rp_filter` on `xpf-usp0`
(`sysctl net.ipv4.conf.xpf-usp0.rp_filter` — must be 0).

### Lab hygiene

On userspace `loss` after a remote host reboot:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs
```

If you are deploying a fresh build:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

## Standard Artifact Collection

Every failover run should leave enough evidence to answer:

1. Did ownership move?
2. Did traffic stay up?
3. If traffic failed, where did it die?

Minimum artifacts:

- `show chassis cluster status` from both nodes
- `show chassis cluster data-plane statistics` from both nodes
- `show chassis cluster data-plane interfaces` from both nodes
- `show security flow session destination-prefix <target>` from both nodes
- host-side `iperf3` JSON or log
- any script artifact directory under `/tmp`

For userspace RG-move testing, the hardened validator already captures these.

## Userspace Failover Test Matrix

Run these in order. Do not skip ahead. A broken earlier phase invalidates the
later ones.

### 1. Steady-state userspace validation

Purpose:

- prove the active node is healthy before introducing failover

This scenario uses a diagnostic walkthrough, not an HA gate (see "HA gates"
above).

Command:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
RUNS=3 DURATION=5 PARALLEL=4 \
PREFERRED_ACTIVE_NODE=0 \
PREFERRED_ACTIVE_RGS="1 2" \
scripts/userspace-ha-validation.sh
```

Pass:

- `.200` and `::200` reachability pass
- no immediate collapse in the steady-state iperf checks
- the intended active node owns the intended RGs

### 2. Hardened RG move under load

Purpose:

- validate RG move and failback while traffic is already established

This scenario uses a diagnostic walkthrough, not an HA gate (see "HA gates"
above).

Baseline command:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=3 CYCLE_INTERVAL=10 \
scripts/userspace-ha-failover-validation.sh --duration 90 --parallel 4
```

Reverse-path follow-up:

```bash
# The validator currently exercises the source-sending path. Run a matching
# reverse iperf after the forward pass so failover is validated in both
# ownership directions.
iperf3 -c 172.16.80.200 -P 4 -t 90 -R
```

Useful knobs:

- `SOURCE_NODE`
- `TARGET_NODE`
- `RG`
- `TOTAL_CYCLES`
- `CYCLE_INTERVAL`
- `CHECK_EXTERNAL_REACHABILITY=0`
  - only when the public/WAN path is already down and you are isolating the
    failover dataplane itself
- `TRANSITION_SAMPLE_SECONDS`
- `REQUIRE_FABRIC_ACTIVITY`

Pass:

- RG ownership moves to the requested node
- immediate target reachability returns quickly after each phase
- no sustained zero-throughput collapse
- both forward and reverse traffic recover after each move
- retransmits stay bounded
- old-owner fabric TX proves stale-owner redirect actually happened
- standby WAN TX stays flat while redirect is expected
- session/neighbor/route/policy deltas stay within threshold

Fail examples:

- `Session misses` spike on the new owner and WAN TX stays near zero
- `iperf3` shows long zero-throughput windows after the RG move
- target stays down until long after the phase timeout

### 3. Manual CLI RG move under active traffic

Purpose:

- reproduce operator-reported failover behavior exactly
- validate the manual CLI path, not just the harness

Start traffic from the host:

```bash
iperf3 -c 172.16.80.200 -P 8 -t 120
```

Then repeat the same test in reverse mode:

```bash
iperf3 -c 172.16.80.200 -P 8 -t 120 -R
```

Move the RG from the current primary:

```bash
cli -c "request chassis cluster failover redundancy-group 1 node 1"
```

Repeat in the opposite direction:

```bash
cli -c "request chassis cluster failover redundancy-group 1 node 0"
```

Pass:

- throughput may dip, but recovers quickly and stays relatively flat in both directions
- new connections succeed immediately after the move
- reverse `iperf3 -R` does not wedge at `0.00 bits/sec`
- the moved RG remains on the requested node

Required live checks during manual RG move:

```bash
cli -c "monitor interface <fabric-parent>"
cli -c "monitor interface <wan-parent>"
cli -c "show chassis cluster data-plane statistics"
cli -c "show security flow session destination-prefix 172.16.80.200/32"
```

### 4. Hard crash / power-cut failover

Purpose:

- validate worst-case failover when the primary does not demote cleanly

From the active primary:

> **WARNING (lab/test environments only):** The following command forces an immediate kernel reboot without syncing disks. It can corrupt filesystems and should only be used in lab or test environments, never on production systems. Requires root. If filesystem safety matters, prefer `systemctl reboot --force` or `reboot -f` instead.

```bash
echo b > /proc/sysrq-trigger
```

Run this with active host traffic already established.

Pass:

- the secondary takes over quickly
- traffic recovers and stays up
- the rebooted node rejoins as secondary
- the rejoin does not kill traffic again

After the rebooted VM comes back:

- verify `show chassis cluster status`
- verify both nodes are healthy
- verify traffic is still flowing

### 5. Rejoin and re-move

Purpose:

- prove that the cluster is still healthy after the crash and rejoin, not just
  that one takeover succeeded

After the crashed node rejoins:

1. start a fresh forward `iperf3 -P 8`
2. start a fresh reverse `iperf3 -P 8 -R`
3. move the RG again with CLI failover
4. verify flows still recover and stay flat in both directions

Pass:

- no new collapse introduced by the rejoined node in either direction
- takeover readiness returns on both nodes

### 6. Split-RG active/active validation

Purpose:

- validate active/active ownership, not just all-RGs-on-one-node

Example target state:

- `RG1` on `node1`
- `RG2` on `node0`

Move the groups explicitly:

```bash
cli -c "request chassis cluster failover redundancy-group 1 node 1"
cli -c "request chassis cluster failover redundancy-group 2 node 0"
```

Then validate:

- both RGs stay on the intended nodes
- both nodes report healthy status
- traffic still passes

Then crash one node with:

WARNING: The following command forces an immediate kernel reboot without syncing disks. It can corrupt filesystems and should only be run in lab/test environments, never on production systems.
```bash
echo b > /proc/sysrq-trigger
```

Pass:

- the surviving node takes over the lost RGs
- traffic continues or recovers quickly
- no stuck `session sync not ready` state remains after convergence

### 7. Multi-cycle stress

Purpose:

- catch flaky handoff paths that pass once and fail later

Recommended:

- run multiple RG move cycles with `TOTAL_CYCLES > 1`
- run crash/rejoin cycles after a successful RG move cycle
- run split-RG crash in both directions

## Makefile HA Smoke Gates

These are the required gates (see "HA gates" above). They run on the loss
userspace cluster by default.

### Reboot/failback survival

```bash
make test-failover
```

This covers:

- active `iperf3` through the primary
- reboot of `fw0`
- failover to `fw1`
- rejoin of `fw0`
- manual failback

### Crash / daemon-stop / multi-cycle

```bash
make test-ha-crash
```

This covers:

- force-stop / power-loss style failover
- daemon stop on the primary
- multi-cycle recovery

### Stress scripts

```bash
make test-double-failover
make test-stress-failover
make test-chained-crash
```

Use these after the basic reboot/crash paths pass.

## Pass Criteria

Do not call failover healthy unless all of the following are true for the
scenario being tested.

- RG ownership moves to the intended node
- no dual-active state appears
- the new owner actually forwards traffic
- the old owner uses the fabric path when stale-owner redirect is expected
- the standby WAN does not leak traffic when it should be inactive
- established flows recover and stay relatively flat
- fresh flows succeed immediately after the move
- the rebooted node rejoins without killing existing traffic
- post-test cluster status is healthy and takeover-ready

## When To Use Packet Capture

Use packet capture only when counters and session state are not enough to
distinguish where the flow died.

On the remote target `.200`, use the gRPC capture/tcpdump workflow already
documented for the lab instead of assuming local shell access. Typical capture
targets:

- host side toward the VIP/target
- primary WAN parent
- primary fabric parent
- secondary fabric parent
- `.200` endpoint

## Common Failure Shapes

### Old owner still receives, new owner never transmits

Likely areas:

- stale-owner redirect path
- helper HA active/inactive state
- synced-session promotion on the new owner

### Fabric RX rises, WAN TX stays flat, session misses spike

Likely areas:

- session import / reverse reconstruction
- wrong HA disposition on inherited sessions
- stale aliasing or wrong owner RG on the new owner

### First probe after restart fails, second succeeds

Likely areas:

- neighbor warmup / pending-neighbor retry
- cold-start helper state

### Crash takeover works, manual RG move fails

Likely areas:

- demotion prep
- barrier / sync readiness
- moved-session invalidation and re-install ordering

## Reset Between Runs

Always restore the cluster before the next scenario.

At minimum:

1. stop any stale `iperf3`
2. verify both VMs are up
3. verify `xpfd` is active
4. verify cluster status is stable
5. reset any stale manual failover flags if needed
6. pin RG ownership to the intended starting node

Userspace example:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
./test/incus/cluster-setup.sh restart all
```

If the goal is only to restore RG placement, use the CLI failover commands and
wait for convergence instead of doing an unnecessary redeploy.

## Recommended Execution Order For Release Validation

Use this order when validating HA/failover for a serious userspace change.
Steps 1 and 2 are the required gates. The rest are manual scenarios that add
coverage the gates do not have. The two diagnostic walkthroughs are optional
pre-checks when steady state is in doubt; they do not replace step 1 or 2.

1. `make test-failover`
2. `make test-ha-crash`
3. manual CLI RG move under forward `iperf3 -P 8`
4. manual CLI RG move under reverse `iperf3 -P 8 -R`
5. hard crash of the active primary with traffic running
6. rebooted-node rejoin validation
7. another manual RG move after rejoin
8. split-RG placement validation
9. split-RG crash in both directions
10. multi-cycle failover stress

If any earlier phase fails, stop and fix that first. Later failover tests are
not trustworthy on top of a broken baseline.
