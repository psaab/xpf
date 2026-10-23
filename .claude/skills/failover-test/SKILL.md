---
name: failover-test
description: Run iperf3 throughput through the HA cluster while cycling RG failovers. Verifies throughput floors with configurable iterations.
user-invocable: true
---

# HA Failover Test Skill

Run iperf3 throughput through the firewall cluster while cycling redundancy-group
failovers. Use the gate-specific thresholds below: the regular failover smoke
permits limited aggregate zero-throughput intervals, while the stress smoke
permits up to one per-stream zero-throughput interval row per requested cycle,
summed across streams.

> **Shared-cluster lock (read first).** The loss userspace cluster is SHARED.
> Build outside the lock, then keep deploy and measurement in ONE cell using
> `./test/incus/with-cluster.sh` (the complete command is under Procedure
> below). A stand-alone `make test-failover` or `make test-stress-failover`
> self-locks; if a deploy precedes a smoke, wrap both together. Never copy
> binaries by hand, issue ad-hoc daemon-control commands, or kill another
> agent's lock holder. See `docs/engineering-style.md` shared-cluster protocol.

## Arguments

- `/failover-test` — standard failover smoke (`make test-failover`)
- `/failover-test N` — N stress cycles (`TOTAL_CYCLES=N make test-stress-failover`)
- `/failover-test N rg2` — N RG2 cycles using the Manual-cell variant below; the make stress target cycles RG1

## Procedure

1. **Build** the packaged artifact before taking the cluster lock (`make deb`).
2. Use the single-cell wrapper below: `/failover-test` selects
   `make test-failover`; `/failover-test N` selects
   `TOTAL_CYCLES=N make test-stress-failover`.

The make-target path performs readiness checks, preflight, RG recording/reset,
failover cycling, and output parsing. Do not hand-run or split those steps when
using a make target. The explicit manual RG2 exception below keeps its complete
custom sequence inside one lock cell.

A standalone deploy uses `make cluster-deploy`, which builds outside the lock
and self-locks its cluster mutation. For a deploy-plus-measurement sequence,
use:

```bash
make deb
./test/incus/with-cluster.sh "failover-test" -- bash -c '
set -euo pipefail
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
    XPF_CLUSTER_SKIP_BUILD=1 ./test/incus/cluster-setup.sh deploy all
# For `/failover-test`, keep this command:
make test-failover
# For `/failover-test N`, use `TOTAL_CYCLES=N make test-stress-failover` instead.
'
```

The external `make deb` above (like `make cluster-deploy`'s deb prerequisite)
is a dogfood/dev build: it does not set `XPF_RELEASE`. A missing archive key
therefore produces a warning and an unpublishable placeholder package. Release
packaging must separately provide the real key and set `XPF_RELEASE=1` (and
`XPF_SIGN_SECKEY` for a signed bake); this failover test is not release-key
validation. The in-cell deploy uses `XPF_CLUSTER_SKIP_BUILD=1`, so it does not
run `make deb` again.

### Manual-cell variant (`/failover-test N rg2`)

The smoke targets do not select RG2. For a manual RG2 run, build first, then
keep deploy, readiness/preflight, all RG2 moves, traffic, restoration, and
parsing in one cell as below. Replace `3` with the requested cycle count. This
manual path's parser applies a single-`[SUM]`-line throughput-floor verdict
only; it is not a substitute for the make target's full gate. The cell body
travels as a file argument with stdin closed (`</dev/null`), and every
`incus exec` carries `-n`: otherwise the first stdin-reading child drains the
rest of the script and the run fails open (#9683).

```bash
make deb
(
cell="$(mktemp "${TMPDIR:-/tmp}/failover-test-rg2.XXXXXX")"
trap 'rm -f "$cell"' EXIT
cat >"$cell" <<'CELL'
set -euo pipefail
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
    XPF_CLUSTER_SKIP_BUILD=1 ./test/incus/cluster-setup.sh deploy all
source test/incus/cluster-env.sh
CLI=/usr/local/sbin/cli
[[ "$TOTAL_CYCLES" =~ ^[1-9][0-9]*$ ]] || { echo "TOTAL_CYCLES must be positive" >&2; exit 2; }

rg2_ready() {
    incus exec -n "$1" -- "$CLI" -c 'show chassis cluster status' |
        awk '/^Redundancy group: 2 ,/ { in_rg=1; next }
             /^Redundancy group:/ { in_rg=0 }
             in_rg && $1 == "Takeover" && $2 == "ready:" { found=1; ready=($3 == "yes") }
             END { exit !(found && ready) }'
}
ready=0
for attempt in $(seq 1 60); do
    ready=1
    for node in "$FW0" "$FW1"; do
        if ! rg2_ready "$node"; then
            ready=0
        fi
    done
    (( ready )) && break
    sleep 1
done
(( ready )) || { echo "RG2 did not become takeover-ready on both nodes" >&2; exit 1; }
./test/incus/target-services.sh check 5211

rg2_owner() {
    incus exec -n "$FW0" -- "$CLI" -c 'show chassis cluster status' |
        awk '/^Redundancy group: 2 ,/ { in_rg=1; next }
             /^Redundancy group:/ { in_rg=0 }
             in_rg && $3 == "primary" { print $1; exit }'
}
await_rg2_owner() {
    local expected="$1" attempt owner
    for attempt in $(seq 1 60); do
        owner="$(rg2_owner)"
        [[ "$owner" == "$expected" ]] && return 0
        sleep 1
    done
    echo "RG2 did not reach $expected (last owner: ${owner:-unknown})" >&2
    return 1
}

initial_owner="$(rg2_owner)"
[[ "$initial_owner" == node0 || "$initial_owner" == node1 ]] ||
    { echo "could not determine RG2's initial owner" >&2; exit 1; }
initial_node="${initial_owner#node}"
log="${TMPDIR:-/tmp}/failover-test-rg2.$$.log"
restore_rg2() {
    local node="$initial_node"
    incus exec -n "$FW0" -- "$CLI" -c 'request chassis cluster failover reset redundancy-group 2' >/dev/null 2>&1 || true
    incus exec -n "$FW1" -- "$CLI" -c 'request chassis cluster failover reset redundancy-group 2' >/dev/null 2>&1 || true
    incus exec -n "$FW0" -- "$CLI" -c "request chassis cluster failover redundancy-group 2 node $node" >/dev/null 2>&1 || true
    await_rg2_owner "$initial_owner" || true
    incus exec -n "$FW0" -- "$CLI" -c 'request chassis cluster failover reset redundancy-group 2' >/dev/null 2>&1 || true
    incus exec -n "$FW1" -- "$CLI" -c 'request chassis cluster failover reset redundancy-group 2' >/dev/null 2>&1 || true
    rm -f "$log"
}
trap restore_rg2 EXIT

duration=$(( TOTAL_CYCLES * 120 + 60 ))
incus exec -n "$CLUSTER_LAN_HOST" -- iperf3 --forceflush --connect-timeout 5000 \
    -t "$duration" -c "$IPERF_TARGET4" -p 5211 -P 4 >"$log" 2>&1 &
iperf_pid=$!
current_owner="$initial_owner"
for (( cycle=1; cycle<=TOTAL_CYCLES; cycle++ )); do
    if [[ "$current_owner" == node0 ]]; then
        alternate_owner=node1
    else
        alternate_owner=node0
    fi
    for target_owner in "$alternate_owner" "$initial_owner"; do
        target_node="${target_owner#node}"
        target_fw="$FW0"
        [[ "$target_node" == 1 ]] && target_fw="$FW1"
        incus exec -n "$target_fw" -- "$CLI" -c \
            "request chassis cluster failover redundancy-group 2 node $target_node"
        await_rg2_owner "$target_owner"
        incus exec -n "$FW0" -- "$CLI" -c 'request chassis cluster failover reset redundancy-group 2'
        incus exec -n "$FW1" -- "$CLI" -c 'request chassis cluster failover reset redundancy-group 2'
        current_owner="$target_owner"
    done
done
wait "$iperf_pid"
source test/incus/iperf-throughput-lib.sh
sum_line="$(grep '\[SUM\]' "$log" | tail -n 1)"
verdict="$(iperf_throughput_verdict 1.0 "$sum_line")"
printf '%s\n' "$verdict"
[[ "$verdict" == PASS\ * ]]
CELL
TOTAL_CYCLES=3 ./test/incus/with-cluster.sh "failover-test-rg2" -- bash "$cell" </dev/null
)
```

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

- `make test-failover`: average throughput at least 1.0 Gbps, at most 2
  consecutive aggregate intervals below that floor, and 0 per-stream
  intervals at or below 50 Mbps.
- `TOTAL_CYCLES=N make test-stress-failover`: final-interval `[SUM]` floor at
  least `MIN_THROUGHPUT` (default 1.0 Gbps), and at most `TOTAL_CYCLES`
  per-stream zero-throughput interval rows summed across streams
  (`test/incus/test-stress-failover.sh:277-301`). This stress allowance means
  zero rows are not an unconditional failure on this path.

`iperf-throughput-lib.sh` supplies a single-`[SUM]`-line floor verdict only; it does not enforce the per-interval or per-stream thresholds above.


## Additional Tests

### Hard crash failover (`/failover-test crash`)

Use `make test-ha-crash` for the hard-crash sequence, or `make test-failover`
for the crash-and-failback smoke. Each target self-locks when run alone; when
deploying first, invoke it inside the same `with-cluster.sh` cell as the deploy.
Do not run an ad-hoc reboot command outside that cell.

RG2 custom moves belong only in the Manual-cell variant above. Never issue a
manual failover or its traffic measurement outside that single `with-cluster.sh`
cell.

## Diagnostics

> **#16111 — in-VM `tcpdump` is blind to AF_XDP fast-path flows.** Do not
> "capture on both nodes" with `tcpdump` (or `monitor traffic`) inside the
> firewall VMs: XDP redirects fast-path frames to the AF_XDP helper before
> any AF_PACKET tap, so a live multi-Gbps flow captures
> `0 packets captured` on `any`, the physical NICs, the `.80` VLAN
> sub-interfaces, the fabric parents, and `xpf-usp0`/`xpf-usp1`. An empty
> in-VM pcap does not prove the traffic never arrived. Working observation
> points are LAN/WAN host captures, the remote-target gRPC capture
> service, and helper-statistics/session deltas on both nodes; see
> `testing-docs/failover-testing.md` ("Observation points").

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

Take the same `show chassis cluster data-plane statistics` readings before
and after the failover event on both nodes and compare the deltas; the
counter movement, not an in-VM pcap, proves which node saw the flow.

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
