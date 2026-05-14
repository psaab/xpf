---
name: userspace-ha-validation
description: Validate the isolated loss userspace HA cluster, including fallback-state checks, IPv6 router advertisements, repeated IPv4/IPv6 iperf3 runs, and optional perf capture on the active firewall.
---

# Userspace HA Validation

Use this skill when the task is to validate the isolated userspace HA cluster on
`loss`, especially after dataplane or HA changes.

Cluster inputs:
- env file: `test/incus/loss-userspace-cluster.env`
- config: `docs/ha-cluster-userspace.conf`
- script: `scripts/userspace-ha-validation.sh`
- phase cycle: `scripts/userspace-phase-cycle.sh`
- perf compare: `scripts/userspace-perf-compare.sh`

Workflow:

1. After each userspace dataplane phase, run the phase-cycle script from the repo root.
2. The phase-cycle script pushes the current branch, deploys `xpf-userspace-fw0/1`, and then runs the validation script.
3. Use `--perf` when the phase needs fresh `perf` profiles on whichever userspace firewall is active after deploy.
4. Treat the validator threshold as the target for the current tree, not as proof that the
   current tree state already meets it.

Commands:

```bash
./scripts/userspace-phase-cycle.sh
./scripts/userspace-phase-cycle.sh --perf
./scripts/userspace-perf-compare.sh
```

What the script enforces:

- `xpfd` is reachable on both isolated firewalls before validation samples dataplane state
- the runtime must settle cleanly into either supported userspace forwarding or legacy fallback
- `cluster-userspace-host` is forced to keep accepting IPv6 RAs before route checks
- `cluster-userspace-host` has an IPv6 default route from RA
- if the IPv6 default route is missing, repeated `rdisc6 -1 eth0` is run before tests
- the active WAN test interface is derived from the current primary node's route table, not hardcoded per chassis
- deterministic TTL-expired probes must work to:
  - `1.1.1.1`
  - `2607:f8b0:4005:814::200e`
  - `ping` exit status `1` is expected for these probes if the returned output
    contains the native time-exceeded response
- one-cycle `mtr` reports to those two targets must show:
  - a resolved first hop
- a resolved IPv4 destination hop
- for IPv6, an unresolved final public internet hop is a warning after the
  deterministic IPv6 TTL-expired probe has passed
- one unmeasured warm-up `iperf3` pass is run for each address family
- repeated IPv4 `iperf3` to `172.16.80.200` must stay above threshold
- repeated IPv6 `iperf3` to `2001:559:8585:80::200` must stay above threshold
- per-interval `iperf3 -J` output is copied back to the repo host, parsed
  locally, and a run fails if it starts fast and then collapses
- one marginal near-threshold miss is retried once before the run is treated as failed
- optional `perf` capture runs on the active userspace firewall, not a hardcoded node

Use `scripts/userspace-ha-validation.sh` directly only when you are debugging the validator itself.

`cluster-userspace-host` only needs `ping`, `mtr`, and `iperf3`. The JSON
interval analysis runs on the repo host with `scripts/iperf-json-metrics.py`,
so do not assume `python3` exists on the test host.

Use `scripts/userspace-perf-compare.sh` when validation is failing or when you need fresh IPv4/IPv6 hotspot data without the validator's throughput gates. Read [docs/userspace-perf-compare.md](/home/ps/git/codex-xpf/docs/userspace-perf-compare.md) for the exact artifact layout and interpretation.

The current tree reality is:

- the Rust userspace dataplane is real and deployed on the isolated `loss` userspace lab
- the validator must distinguish between intentional fallback and real userspace forwarding
- the legacy XDP dataplane is still the correctness and performance reference
- `22-23 Gbps` is the target, not the guaranteed result of every current tree state
- the default `PARALLEL=6` is intentional for the six-worker AF_XDP lab shape;
  use a lower explicit `PARALLEL` only when studying low-flow/RSS behavior

If the script fails on IPv6 route state:

1. check `show ipv6 router-advertisement` on `xpf-userspace-fw0`
2. verify the running config came from `docs/ha-cluster-userspace.conf`
3. do not treat `/tmp/ha-cluster-userspace.conf` as authoritative
