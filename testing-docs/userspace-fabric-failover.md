# Userspace Fabric Failover

This document covers the userspace HA failover case where redundancy-group
ownership moves to the peer and existing traffic must cross the inter-node
fabric path during the transition.

This is the failure mode that used to look "mostly fine" in aggregate while
still being wrong in practice:

- `iperf3` eventually recovered, but there were real zero-throughput intervals
- external IPv4 or IPv6 broke only on the new owner
- traffic hit the wrong owner but did not redirect across the fabric cleanly
- stale MAC traffic died on the old owner because the standby helper was not
  armed
- failover passed a loose throughput threshold while still accumulating
  session, neighbor, or policy failures during the move

The goal of the hardened validator is to detect those cases directly.

## What we proved in the latest hardening pass

The most important correction from the latest live work on `loss`:

- stale-owner traffic was not leaking out the standby WAN
- it was redirecting across the fabric correctly
- the real remaining failure was performance on the copy-mode fabric path

Fresh failover deltas and `monitor interface` output showed:

- standby WAN `ge-7-0-2` stayed flat during the stale-owner test
- fabric parent `ge-7-0-0` / `fab1` carried the redirected traffic
- the fabric parent is `virtio_net` in copy mode, not `mlx5` zero-copy

That distinction matters. A low stale-owner bitrate is not automatically a
fabric-redirect correctness bug.

## Current validator

Primary script:

```bash
scripts/userspace-ha-failover-validation.sh
```

Baseline command (the validator self-selects `IPERF_TARGET4` from the
default `test/incus/loss-userspace-cluster.env`; loss today 172.16.80.202,
#18576 — do not pin `IPERF_TARGET=172.16.80.200`, which the external box
still answers):

```bash
TOTAL_CYCLES=3 CYCLE_INTERVAL=10 \
scripts/userspace-ha-failover-validation.sh --duration 90 --parallel 4
```

What it now checks:

1. steady-state target reachability before failover
2. continuous `iperf3` health through RG move and failback
3. external IPv4 and IPv6 reachability immediately after each phase and after
   the post-phase observe window
4. standby helper readiness on the old owner after each move
5. evidence that the old owner actually transmitted on the fabric path during
   the phase
6. bounded failover deltas for:
   - session misses
   - neighbor misses
   - route misses
   - policy denied packets
7. post-run throughput, retransmits, and zero-throughput interval counts

If steady-state preflight already shows the public targets are unreachable,
isolate that outage before judging the failover path. The harness supports
`CHECK_EXTERNAL_REACHABILITY=0` for those cases so you can still validate
userspace RG-move continuity without masking the fact that internet coverage
was not exercised.

## Why we hardened it this way

The old validator proved only that a long-lived `iperf3` run did not fully die.
That was not enough.

We saw real bad states that could still pass a loose end-of-run throughput
check:

- old owner stopped redirecting to the peer fabric
- new owner blackholed external IPv4 but not IPv6
- stale sessions or reverse-session reconstruction caused short but real
  throughput collapses
- the standby helper fell out of the userspace path and traffic died only
  during failback
- the test did not prove the fabric path was exercised at all

So the validator now has to answer three separate questions:

1. Did traffic stay up?
2. Did the correct node own the flow after the move?
3. Did the old owner actually use the fabric redirect path while stale-MAC
   traffic still landed there?

## Historical fixes that got failover to the current state

These are the main changes that materially improved userspace HA failover.

### 1. Fabric redirect runtime state had to be complete

Problem:

- the helper could not always reconstruct a usable fabric redirect from the
  runtime snapshot alone
- stale-MAC traffic on the old owner died instead of crossing the fabric

Fix:

- publish explicit fabric MAC state in the snapshot
- rebuild userspace fabric redirect state from those snapshot MACs

Effect:

- the old owner could actually transmit stale-MAC traffic to the peer

### 2. Reverse synced sessions could not be mirrored blindly

Problem:

- mirroring both forward and reverse cluster-synced sessions poisoned NAT
  semantics on the peer
- reply traffic re-resolved toward the SNAT VIP instead of reversing back to
  the client

Fix:

- mirror only the forward synced entry into the helper
- let the helper derive the reverse session locally from forward metadata and
  the NAT reverse index

Effect:

- failover stopped killing the established TCP flow outright

### 3. Synced sessions had to preserve `fabric_ingress`

Problem:

- session sync lost whether the original flow arrived from the peer fabric
- the new owner rebuilt synced sessions as if they were local ingress sessions

Fix:

- export and preserve `fabric_ingress` through the userspace session delta and
  sync path

Effect:

- takeover kept the same fabric-aware reverse-path semantics as the original
  session

### 4. Passive peer reverse resolution had to prefer local delivery when it owned the client-side RG

Problem:

- the passive peer kept bouncing reverse traffic back onto the fabric even when
  it already owned the client-side RG
- that created line-rate startup followed by stream collapse

Fix:

- keep `fabric_ingress` as a hint, not an unconditional redirect instruction
- resolve locally when the peer actually owns the return path

Effect:

- split-RG steady state stopped collapsing before failover even happened

### 5. Standby nodes had to stay armed

Problem:

- standby helpers were previously left disabled or unarmed when no local data
  RG was active
- traffic landing on the old owner during failback fell out of the userspace
  fabric path

Fix:

- keep the standby helper armed with bindings ready whenever userspace
  forwarding is supported and data RGs exist

Effect:

- failback no longer depended on the standby helper cold-starting under load

### 6. External reachability had to be part of the failover gate

Problem:

- `.200` traffic and even `iperf3` could look alive while external IPv4 or IPv6
  was broken on the new owner

Fix:

- add external IPv4 and IPv6 checks to the failover validator

Effect:

- node-specific WAN ownership bugs stopped hiding behind internal traffic

### 7. Neighbor ownership had to move into the helper

Problem:

- the old manager-pushed neighbor snapshot was eventually consistent and
  time-based
- cold startup and failover still showed missing-neighbor behavior even after
  several incremental fixes

Fix:

- move initial neighbor dump and RTNL subscribe into the helper
- gate startup on helper-owned neighbor readiness

Effect:

- cold `.200` / `::200` bring-up became materially cleaner

### 8. Helper HA state had to be refreshed from the live RG map

Problem:

- after RG moves, the helper could still retain stale `active=false` state on
  the new owner
- that caused `ha_inactive` behavior even though the cluster had already moved

Fix:

- refresh map-derived HA state and republish it into the helper when it
  diverges

Effect:

- failover ownership inside the helper now matches the live RG map more
  reliably

### 9. Single-interface monitor output had to expose userspace dataplane state

Problem:

- `monitor interface <iface>` did not surface the helper-side userspace view
- operators could see link counters, but not whether an interface had userspace
  bindings, misses, copy/direct TX, or exceptions

Fix:

- extend the gRPC monitor-interface response to include userspace dataplane
  state for the selected interface

Effect:

- live failover debugging can now distinguish:
  - no traffic on the old owner
  - correct fabric redirect on the old owner
  - copy-mode fabric performance collapse on the old owner

### 10. Fabric redirect had to spread across all fabric queues

Problem:

- stale-owner redirects inherited ingress queue affinity
- the copy-mode fabric parent could leave most queues idle while one or two
  queues accumulated the whole redirected workload

Fix:

- hash fabric redirects across all bindings on the target fabric interface
  instead of preserving ingress queue affinity

Effect:

- stale-owner fabric traffic now spreads across the available fabric queues
- this improved throughput and reduced the worst per-queue hot spots, even
  though the fabric path is still fundamentally limited by `virtio_net`
  copy-mode TX

### 11. L4 checksum recompute had to stop allocating per packet

Problem:

- `checksum16_ipv4` / `checksum16_ipv6` still built temporary vectors in the
  hot stale-owner path
- perf kept showing checksum work as a visible local hotspot

Fix:

- switch pseudo-header checksum calculation to a zero-allocation incremental sum

Effect:

- checksum allocation noise dropped out of the top stale-owner profile
- the remaining hot path is now mostly:
  - `poll_binding`
  - `__xsk_generic_xmit`
  - `virtqueue_add_outbuf`

## What the hardened validator proves now

For each failover or failback phase, it captures pre-phase and post-phase
dataplane state and evaluates:

### 1. Immediate target reachability

The script verifies that the host can still reach `${IPERF_TARGET}` right after
the RG move and again after the post-phase interval.

This catches:

- redirect path failure even when `iperf3` is still retrying
- first-hit target unreachability masked by later recovery

### 2. Standby readiness

The old owner must remain:

- `Enabled: true`
- `Forwarding armed: true`
- `Ready bindings: > 0`
- `rg<id> active=false`

This catches:

- standby helper drop-out
- failback regressions caused by the old owner leaving the userspace path

### 3. Fabric-path evidence

The script sums `TXPkts` on the current fabric parent bindings and requires a
positive delta on the old owner across the phase by default.

This catches:

- failover tests that never actually exercised the fabric path
- real redirect failures where stale-MAC traffic landed on the old owner but
  was not transmitted across the fabric

Relevant tuning:

- `REQUIRE_FABRIC_ACTIVITY=1`
- `MIN_FABRIC_TX_DELTA=1`
- `FABRIC_ACTIVITY_TRIGGER_DELTA=8`

Current rule:

- require positive old-owner fabric TX only when the old owner accumulated at
  least `8` units of failover churn across:
  - session misses
  - neighbor misses
  - route misses
  - policy denied packets
- otherwise record the phase as "no stale-owner fabric activity required"

This avoids false failures on clean RG moves where traffic never needed to
traverse the stale owner during the measurement window.

### 4. Phase miss and deny deltas

The script compares pre-phase and post-phase cumulative counters across both
nodes for:

- `Session misses`
- `Neighbor misses`
- `Route misses`
- `Policy denied packets`

Default thresholds:

- `MAX_FAILOVER_SESSION_MISS_DELTA=64`
- `MAX_FAILOVER_NEIGHBOR_MISS_DELTA=60`
- `MAX_FAILOVER_ROUTE_MISS_DELTA=32`
- `MAX_FAILOVER_POLICY_DENIED_DELTA=0`

These values were tuned from live `loss` userspace-cluster artifacts:

- clean failover phases stayed around session-miss deltas of `10-28`
- clean failover phases stayed around neighbor-miss deltas of `0-52`
- route-miss and policy-deny deltas stayed at `0`

This catches:

- partial failover success with hidden dataplane churn
- redirect regressions that recover eventually but do so by missing and
  re-learning too much state
- reverse-path failures that manifest as policy deny spikes

## How to read failures

### `fabric TX delta 0`

Meaning:

- either the test did not actually exercise stale-MAC fabric traversal
- or the old owner failed to redirect traffic onto the fabric

First checks:

1. confirm the old owner stayed armed
2. inspect `Recent userspace exceptions` in the phase artifacts
3. check whether the host refreshed MAC/neighbor state too quickly for the
   phase to require fabric traversal

### `policy denied delta > 0`

Meaning:

- traffic reached a node that did not reconstruct the expected session or
  reverse-path metadata

Typical root causes:

- stale HA state
- bad reverse-session semantics
- wrong owner return-path resolution

### `session miss delta` or `neighbor miss delta` too high

Meaning:

- the failover recovered through churn rather than preserving the flow cleanly

Typical root causes:

- helper neighbor state not ready
- route or next-hop prewarm missing
- fabric-ingress continuity not preserved

### Fabric TX is present but throughput is still poor

Meaning:

- redirect correctness is likely fine
- the old owner is using the fabric path
- the remaining issue is the quality of the copy-mode fabric dataplane

Typical causes:

- `virtio_net` fabric parent in copy mode
- poor queue spread on the fabric parent
- high retransmits on the redirected TCP streams

Use `monitor interface ge-*-0-0` on the stale owner and check:

- `Copy TX packets`
- queue-level activity
- `Binding errors`
- recent exceptions

If WAN egress on the standby stays flat while fabric TX rises, treat this as a
performance issue, not a missing-redirect issue.

### external IPv4 or IPv6 fails while the test target survives

Meaning:

- failover ownership moved far enough for the test target, but the new WAN
  owner is still wrong or incomplete

Treat this as a real HA failure. Internal target reachability alone is not
enough.

## Operational procedure for a credible failover run

1. Refresh VF state after any reboot of the `loss` host.

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs
```

2. Deploy the intended build.

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

3. Pin the intended RG placement before comparing results.

4. Run the failover validator with enough duration for the planned cycle count.

For multi-cycle runs, let the script choose the duration unless you have a
specific reason to override it. The hardened validator now reserves time for:

- sync wait
- pre-failover observe
- both RG moves per cycle
- failover settle time per cycle

5. Check both the summary output and the artifact directory.

6. Treat any of these as a real regression:
   - zero-throughput intervals
   - dead streams
   - external reachability failures
   - standby not armed
   - fabric TX delta not positive when old-owner churn exceeds the trigger
   - miss/deny deltas over threshold

## Manual stale-owner workflow

When a report says "traffic is still showing up on the standby WAN," use this
workflow before assuming redirect is broken:

```bash
# Source the cluster env first so $IPERF_TARGET4 resolves (loss: .202, #18576).
source test/incus/cluster-env.sh

# 1. Force RG1 to node0 so node1 becomes the stale owner for LAN ingress.
incus exec loss:xpf-userspace-fw1 -- \
  bash -lc 'cli -c "request chassis cluster failover redundancy-group 1 node 0"'

# 2. Watch both the standby WAN and the standby fabric parent.
incus exec loss:xpf-userspace-fw1 -- \
  bash -lc 'timeout 5 cli -c "monitor interface ge-7-0-2"'
incus exec loss:xpf-userspace-fw1 -- \
  bash -lc 'timeout 5 cli -c "monitor interface ge-7-0-0"'

# 3. Drive traffic from the LAN host.
incus exec loss:cluster-userspace-host -- \
  bash -lc "ping -c 5 $IPERF_TARGET4 >/dev/null && iperf3 -J -c $IPERF_TARGET4 -P 4 -t 5"
```

Read the result like this:

- `ge-7-0-0` TX rises, `ge-7-0-2` TX flat:
  - redirect is working
- `ge-7-0-2` TX rises materially while RG1 is inactive there:
  - real standby WAN leak / owner-state bug
- `ge-7-0-0` TX rises but bitrate is low and retransmits are high:
  - copy-mode fabric path is the bottleneck

## Artifact files worth checking first

For each phase:

- `cycle<n>-<phase>-pre-fw0-dp-stats.txt`
- `cycle<n>-<phase>-pre-fw1-dp-stats.txt`
- `cycle<n>-<phase>-post-fw0-dp-stats.txt`
- `cycle<n>-<phase>-post-fw1-dp-stats.txt`

Then:

- `iperf3.log`
- `iperf3.metrics.json`
- `external-*.txt`

Those are the first files to compare when a phase reports:

- missing fabric TX
- policy deny spikes
- unexpected session or neighbor churn
- external IPv4 or IPv6 loss

For stale-owner performance analysis, also capture:

- one `monitor interface ge-*-0-0` sample on the stale owner
- one `monitor interface ge-*-0-2` sample on the stale owner
- the `iperf3` JSON so retransmits can be compared against the fabric counters
