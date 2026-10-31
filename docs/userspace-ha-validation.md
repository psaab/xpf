# Userspace HA Validation

Date: 2026-03-14

This document captures the current repeatable validation path for the isolated
userspace cluster on `loss`:

- `loss:xpf-userspace-fw0`
- `loss:xpf-userspace-fw1`
- `loss:cluster-userspace-host`

Tracked inputs:
- env: [loss-userspace-cluster.env](../test/incus/loss-userspace-cluster.env)
- config: [ha-cluster-userspace.conf](../docs/ha-cluster-userspace.conf)
- validator: [userspace-ha-validation.sh](../scripts/userspace-ha-validation.sh)
- failover validator: [userspace-ha-failover-validation.sh](../scripts/userspace-ha-failover-validation.sh)
- phase cycle: [userspace-phase-cycle.sh](../scripts/userspace-phase-cycle.sh)
- perf compare: [userspace-perf-compare.sh](../scripts/userspace-perf-compare.sh)
- failover parity plan: [userspace-ha-failover-parity-plan.md](../docs/userspace-ha-failover-parity-plan.md)

## Current Model

The isolated userspace cluster is a userspace forwarding development lab. The
validation workflow has to catch two classes of failure:

- hard failures: reachability, RA/default-route, helper/runtime readiness
- soft failures: a run starts fast, then drops to near-zero after the first one or
  two seconds

On `cluster-userspace-host`, the minimum correctness bar remains:
- IPv4 reachability to `172.16.80.200`
- IPv6 reachability to `2001:559:8585:80::200`
- IPv6 default route learned from RA on `eth0`

## Repeatable Validation

Run:

```bash
./scripts/userspace-ha-validation.sh
```

Optional redeploy before test:

```bash
./scripts/userspace-ha-validation.sh --deploy
```

Optional perf capture on the active userspace firewall:

```bash
./scripts/userspace-ha-validation.sh --perf
```

Perf-only compare workflow:

```bash
./scripts/userspace-perf-compare.sh
```

Dedicated RG failover survivability workflow:

```bash
TOTAL_CYCLES=12 CYCLE_INTERVAL=5 \
./scripts/userspace-ha-failover-validation.sh --duration 600 --parallel 8
```

Dedicated aged-failover workflow (#16217 never-again gate; streams
age 30 s before one RG1 failover, acceptance is zero zero-intervals —
expect FAIL until the HA-inactive leg in
[ha-failover-status.md](ha-failover-status.md) is closed):

```bash
./scripts/userspace-ha-failover-validation.sh --aged-failover --duration 60 --parallel 4
```

Dedicated steady-state split-RG fabric workflow:

```bash
./scripts/userspace-ha-failover-validation.sh --steady-only --source-node 1 --target-node 0
```

Standard phase workflow:

```bash
./scripts/userspace-phase-cycle.sh
./scripts/userspace-phase-cycle.sh --perf
```

This is the required sequence after each userspace dataplane phase:

1. commit the phase
2. push the current branch to GitHub
3. deploy to:
   - `loss:xpf-userspace-fw0`
   - `loss:xpf-userspace-fw1`
4. run the isolated userspace HA validation script

For failover-specific HA/session work, also run the dedicated RG failover
validator. The steady-state validator is not enough to prove that an existing
TCP flow survives a manual RG ownership move.

The standard failover stress shape is now:

- a long-lived `iperf3` run, not a short smoke pass
- `-P 8` so all stream lines stay visible during the move
- rapid RG1 movement between `fw0` and `fw1` with `CYCLE_INTERVAL=5`
- enough total cycles and duration to catch late failback wedges, not just the
  first transition

For fabric-path performance and stream-stability work, also run the failover
validator in `--steady-only` mode with RG1 pinned to the peer owner. That
isolates the split-RG fabric path without failover churn and catches
"starts fast, then all streams go to 0" regressions before any RG transition.

Current use of that gate:

- `--steady-only --source-node 1 --target-node 0` is the standard split-RG
  fabric-path repro for the isolated userspace lab
- the acceptance bar is:
  - `0` aggregate zero-throughput intervals
  - `0` per-stream zero-throughput intervals
  - all streams still carrying traffic at the end of the steady-state window

If the validation script is failing and you still need current performance data,
run the perf-compare workflow next. It captures IPv4/IPv6 `iperf3` and `perf`
artifacts without treating current tree instability as a hard blocker.

## What The Validator Enforces

The validator does this in order:

1. uses the tracked env/config in the repo, not `/tmp`
2. waits for CLI availability on both firewalls
3. fails unless the runtime settled into supported userspace forwarding; legacy
   eBPF fallback requires explicit `ALLOW_LEGACY_EBPF_HA_VALIDATION=1`
4. pins the validation RGs to the preferred node, retrying transient failover
   precondition failures while userspace XSK liveness propagates into RG
   readiness
5. forces `cluster-userspace-host` to keep accepting IPv6 RAs (`accept_ra=2`)
6. verifies an IPv6 default route on `cluster-userspace-host`
7. if needed, runs repeated `rdisc6 -1 eth0` to force fresh RA convergence
8. derives the active WAN test interface from the current primary node's route table
9. runs deterministic TTL-expired probes to:
   - IPv4 `1.1.1.1`
   - IPv6 `2607:f8b0:4005:814::200e`
   - the validator treats `ping` exit status `1` as expected for these probes
     when the returned output contains the native time-exceeded response
10. asserts the controlled LAN-to-WAN-target reachability ping received
    replies for both families (the `validate_reachability` gate — this is
    the IPv6 dataplane forwarding-correctness signal, since the LAN host
    reaches the WAN-side target only by transiting the userspace dataplane),
    and asserts the targets do not resolve on-box (`assert_forwarding_route`)
11. records one-cycle `mtr` reports to the public IPv4/IPv6 targets
12. for IPv4 (a reliable responder, `1.1.1.1`), fails if the first hop or the
    final destination hop is unresolved (loss parsed numerically; a
    `(waiting for reply)` / truncated-`%` / `100%` final hop fails closed).
    For IPv6 the public `mtr` is observability-only: an unresolved first hop
    still fails, but any unresolved/silent later or final hop is recorded as
    a warning. External internet IPv6 routing is not gated by the public
    trace — it is gated by the controlled ping/TTL/iperf3 legs to the
    in-control WAN target (see #1303)
13. runs one unmeasured warm-up `iperf3` pass for IPv4 and IPv6
14. runs repeated IPv4 `iperf3` to `172.16.80.200`
15. runs repeated IPv6 `iperf3` to `2001:559:8585:80::200`
16. pulls `iperf3 -J` JSON back to the repo host, parses it locally, and fails
    if throughput cliffs after startup
17. retries one marginal near-threshold miss once
18. optionally records `perf` data on the active firewall

The dedicated RG failover validator now adds stricter HA gates:

1. a steady-state pre-failover observation window after session sync completes
2. `0.00 bits/sec` enforcement during that window for both:
   - aggregate `[SUM]` output
   - individual `iperf3` streams
3. standby userspace readiness checks after each RG move
4. flat standby WAN TX deltas during stale-owner fabric redirect checks

For standard HA failover stress on `loss`, use:

- `TOTAL_CYCLES=12`
- `CYCLE_INTERVAL=5`
- `--duration 600`
- `--parallel 8`
- one forward run and one reverse `iperf3 -R` run

That is the preferred repro shape for the remaining "first failover degrades,
failback wedges one stream" class because it exercises:

- longer-lived inherited flows
- repeated ownership changes in both directions
- per-stream survival, not just aggregate throughput
- both traffic ownership directions, not only the host-sending path

This matters because a split-RG fabric-path bug can kill streams before the
first failover. That must fail as a fabric regression, not be misclassified as
a failover-survivability regression.

### `make test-failover` zero-interval cells: windows and definitions

`scripts/iperf-json-metrics.py` scores the whole-run iperf3 stream.

- **Thresholds.** A per-stream interval counts as "zero" at or below
  `--zero-gbps` (default 0.05 Gbit/s), not only at 0 bytes.
  `zero_intervals_total` (the "whole-run zero-throughput intervals" cell,
  limit 2) is aggregate zero intervals PLUS per-stream zero intervals. It is
  not window-excluded, so one 3 s crash outage across 8 streams already reads
  as 24+ there. Count a run by the same definition before comparing numbers:
  an exact-zero count of the #18598 gate's master arm gives 35, the harness
  definition gives 3 + 58 = 61.
- **Transition windows.** Only `stream_zero_intervals_outside_events_total`
  (the per-stream "outside transition windows" cell, `MAX_STREAM_ZERO_INTERVALS`)
  excludes full intervals inside `[T, T+3]` around each registered event.
  The registered events are:
  - the crash instant (`failover_at_seconds`);
  - the manual RG1 move that starts the split slice, with RG1 on node0 and
    RG0/RG2 on node1 (`rg1_move_at_seconds`, taken at the request, #18617
    follow-up);
  - the last RG of the manual failback (`failback_at_seconds`).

  Before the RG1 move was registered, a stall at that legitimate split move
  was counted as "outside transition windows".

## Target And Interpretation

Validation target for the active userspace forwarding path:

- IPv4 `iperf3 -P 6 -t 5`: `22-23 Gbps`
- IPv6 `iperf3 -P 6 -t 5`: `22-23 Gbps`
- Retransmits: `0`
- Sustained transfer: no “fast first second, then collapse to 0 bps” interval pattern

The default `PARALLEL=6` is intentional for the six-worker AF_XDP lab shape:
the smoke test should cover the worker/RSS set. Use an explicit lower
`PARALLEL` value when studying low-flow RSS behavior; do not treat a
worker-underdriven run as the dataplane ceiling.

That is the target, not a guarantee of the current tree state.

Current `master` reality:

- the isolated HA lab is used for both active userspace-forwarding work and
  explicit legacy regression coverage, depending on the active config and
  runtime gate
- the userspace validator fails by default if the node settled into legacy eBPF
  fallback; set `ALLOW_LEGACY_EBPF_HA_VALIDATION=1` only for a deliberately
  scoped legacy regression run
- the tree is still under active forwarding-correctness and performance work on
  the AF_XDP fast path
- it is normal for the validator to fail while a phase is in progress
- a failing validation run is signal; do not “fix” it by lowering the threshold

Use [userspace-perf-compare.md](../docs/userspace-perf-compare.md)
for the current measured numbers and current hot-path deltas. This document defines
the required workflow and the target, not the current performance claim for every
tree state.

The validator now treats interval collapse as a separate failure mode from average
Gbps. A run that peaks high and then drops near zero is a failure even if the short
overall average still looks superficially acceptable.

For the dedicated failover workflow, the operator should watch all eight stream
lines, not only the `[SUM]` line, for both:

- forward `iperf3 -c ...`
- reverse `iperf3 -c ... -R`

A run is still a failure if aggregate traffic recovers but one stream remains
pinned at `0.00 bits/sec` after failback, or if only one direction recovers.

The validator treats forwarding correctness and traceroute visibility as
distinct concerns. It does not require every internet hop to answer. It does
require:

- the controlled LAN-to-WAN-target ping (`172.16.80.200` /
  `2001:559:8585:80::200`) to receive replies for both families. The LAN
  host reaches these WAN-side targets only by transiting the userspace
  dataplane, so this is the controlled IPv6/IPv4 forwarding-correctness gate
  (`validate_reachability`). It also asserts the targets do not resolve
  on-box, so the transit premise cannot silently drift
  (`assert_forwarding_route`)
- the firewall hop to answer TTL-expired probes
- the final destination hop in IPv4 `mtr` to resolve for `1.1.1.1`. Loss is
  parsed numerically, so a final hop printed as `(waiting for reply)`, with
  a column-truncated loss (`100.0` without `%`), with integer `100%` loss,
  or with an unparseable loss column fails closed
- IPv6 `mtr` to have a resolved first hop. The public IPv6 trace to
  `2607:f8b0:4005:814::200e` is **observability-only**: any unresolved or
  silent later/final hop is recorded as a warning, never a hard failure,
  because the external endpoint and intermediate ICMPv6 rate-limiting are
  outside our control (#1303). IPv6 dataplane forwarding is gated by the
  controlled ping/TTL/iperf3 legs above, not by this external trace

For the TTL / hop-limit probes, a non-zero `ping` exit code is not itself a
failure. The validator accepts the probe when the returned output contains the
expected native time-exceeded text from the userspace firewall.

Artifacts kept on `cluster-userspace-host`:

- `/tmp/userspace-ping-v4.out`
- `/tmp/userspace-ping-v6.out`
- `/tmp/userspace-ttl-v4.txt`
- `/tmp/userspace-ttl-v6.txt`
- `/tmp/userspace-mtr-v4.txt`
- `/tmp/userspace-mtr-v6.txt`
- `/tmp/ipv4-*.json`
- `/tmp/ipv6-*.json`

The `cluster-userspace-host` only needs the runtime tools used to generate the
artifacts:

- `ping`
- `mtr`
- `iperf3`

The interval-collapse analysis runs on the repo host using
[iperf-json-metrics.py](../scripts/iperf-json-metrics.py),
so the cluster test host does not need `python3`.

Short-lived outliers can still happen immediately after rolling deploy while HA
ownership and RA converge. That is why the validator explicitly waits for IPv6
route state before throughput checks.

## Operational Rule

For the isolated userspace cluster, do not use `/tmp` cluster env/config files
as the source of truth.

Use:

- [loss-userspace-cluster.env](../test/incus/loss-userspace-cluster.env)
- [ha-cluster-userspace.conf](../docs/ha-cluster-userspace.conf)
- [userspace-phase-cycle.sh](../scripts/userspace-phase-cycle.sh)
