---
name: failover-test
description: Run iperf3 throughput through the HA cluster while cycling RG failovers. Verifies zero-drop failover with configurable iterations.
user-invocable: true
---

# HA Failover Test Skill

Run iperf3 traffic through the firewall cluster while cycling redundancy-group failovers. Every 1-second interval must maintain throughput between ~4 Gbps (split-RG fabric) and ~22 Gbps (same-node). Zero intervals at 0 Gbps.

> **Shared-cluster lock (read first).** The loss userspace cluster is SHARED.
> Build outside the lock, then keep deploy and measurement in ONE cell using
> `./test/incus/with-cluster.sh` (the complete command is in Build and Deploy
> below). A stand-alone `make test-failover` or `make test-stress-failover`
> self-locks; if a deploy precedes a smoke, wrap both together. Never copy
> binaries by hand, issue ad-hoc daemon-control commands, or kill another
> agent's lock holder. See `docs/engineering-style.md` shared-cluster protocol.

## Arguments

- `/failover-test` — 2 cycles (default)
- `/failover-test 5` — 5 cycles
- `/failover-test 3 rg2` — 3 cycles on RG2 (manual-cell variant; the stress smoke cycles RG1)

## Procedure

1. **Build** the packaged artifact before taking the cluster lock (`make deb`)
2. In one lock cell, deploy through `cluster-setup.sh deploy all`, then use
   `make test-failover` (or `make test-stress-failover` for repeated cycles)
3. Detect environment (loss userspace cluster preferred, local cluster fallback)
4. Wait for cluster readiness (both nodes `Takeover ready: yes`, up to 60s)
5. Pre-flight: both nodes active, helpers running, cluster healthy, iperf3 connectivity to 172.16.80.200
6. Record initial RG ownership
7. Any manual four-stream iperf3 client must use
   `-P 4 -p 5211 --forceflush`; prefer the make smoke targets, which set the
   unshaped port themselves
8. Wait for stabilization, cycle failovers, and collect iperf3 output
9. Parse SUM intervals: PASS if all > 3 Gbps, FAIL if any = 0
10. Reset RGs to original owners

The make smoke targets are the preferred measurement path. They use the shared
cluster lock, and `test-failover.sh` / `test-stress-failover.sh` select the
unshaped iperf3 port. For a deploy followed by a smoke, use the single enclosing
cell below rather than separate lock acquisitions.

ALWAYS build before running tests. A standalone deploy uses `make cluster-deploy`,
which builds outside the lock and self-locks its cluster mutation. For a
deploy-plus-measurement sequence, build first and put both cluster operations
in one cell:

```bash
make deb
./test/incus/with-cluster.sh "failover-test" -- bash -c '
set -euo pipefail
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
    XPF_CLUSTER_SKIP_BUILD=1 ./test/incus/cluster-setup.sh deploy all
make test-failover
'
```

`cluster-setup.sh deploy all` uses the verified deployment path; its internal
build is skipped because the artifact was built before entering the cell. A
standalone smoke target self-locks. To run N stress cycles instead, use
`TOTAL_CYCLES=N make test-stress-failover` inside the same cell as the deploy.
Never run a manual binary-copy recovery: rerun the verified deploy path.

## Environment

`test/incus/cluster-env.sh` derives the instance refs from the env file
(`test/incus/loss-userspace-cluster.env` by default; `BPFRX_CLUSTER_ENV=` selects
the local defaults, `CLUSTER_ENV=` the same via make):

```
loss-userspace-cluster:
  FW0=loss:xpf-userspace-fw0  FW1=loss:xpf-userspace-fw1
  HOST=loss:cluster-userspace-host  TARGET=172.16.80.200
  CLI=/usr/local/sbin/cli
local-cluster:
  FW0=xpf-fw0  FW1=xpf-fw1
  HOST=cluster-lan-host  TARGET=172.16.80.200
```

Mutating and measurement commands belong inside the enclosing lock cell. The
read-only diagnostics below may run outside it.

## Pass/Fail

- PASS: zero intervals at 0, all intervals 3-25 Gbps
- FAIL: any interval at 0 (critical), any below 3 (warning)

Parse with `test/incus/iperf-throughput-lib.sh` (`iperf_throughput_verdict` /
`iperf_throughput_json_verdict`), not an inline Gbits-only grep.

## Additional Tests

### Hard crash failover (`/failover-test crash`)

Use `make test-ha-crash` for the hard-crash sequence, or `make test-failover`
for the crash-and-failback smoke. Each target self-locks when run alone; when
deploying first, invoke it inside the same `with-cluster.sh` cell as the deploy.
Do not run an ad-hoc reboot command outside that cell.

### Manual CLI RG move (`/failover-test manual`)

Prefer `make test-failover` or `make test-stress-failover`, which perform
failover operations inside the lock-aware smoke. Any custom CLI RG move and
iperf3 measurement must be in one `with-cluster.sh` cell; never issue either
operation as a separate shared-cluster command.

## Diagnostics

When a test fails, capture from both nodes (read-only `cli show` commands are
safe to run outside the cell):

```bash
source test/incus/cluster-env.sh
for node in "$FW0" "$FW1"; do
    echo "=== $node ==="
    sg incus-admin -c "incus exec $node -- cli -c 'show chassis cluster status'"
    sg incus-admin -c "incus exec $node -- cli -c 'show chassis cluster data-plane statistics'" | grep -E 'SNAT|Session|Forward|flow cache|installed'
    sg incus-admin -c "incus exec $node -- cli -c 'show security flow session destination-prefix 172.16.80.200/32'" | head -10
done
```

## Known Issues

- iperf3 must be listening on port 5211 for the throughput smoke. Confirm with
  `./test/incus/target-services.sh check 5211`; if the external target service
  is unavailable, stop rather than silently falling back to the default port.
  The default port 5201 maps to the deliberately 100Mbit-shaped `iperf-100m`
  class once CoS is applied. Port 5211 maps to `iperf-uncapped` (no
  `transmit-rate`); `test/incus/iperf-throughput-selftest.sh` guards the
  port-to-class mapping, and `test/incus/target-services.sh up` starts servers
  on the 5200-5211 range when the target is managed by Incus.
- After hard crash, wait 60-90s for the rebooted node to fully rejoin
- If `Takeover ready: no (session sync not ready)` persists > 60s, stop testing,
  capture the read-only diagnostics above, and coordinate before further recovery.
