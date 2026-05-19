# #1373 Retire eBPF Dataplane Blocker Plans

Status: design-plan bundle for #1373 blockers. These docs convert the
reviewed issue contracts into implementation plans for the code PRs that must
land before their listed #1373 retirement phase.

## Blocker Index

| Issue | Plan | Required before | Code PR still needed |
|---|---|---|---|
| #1374 SYN cookie flood protection | [plan-1374-syn-cookies.md](plan-1374-syn-cookies.md) | #1373 Phase 4 | Runtime challenge/ACK/cache/counters landed; bounded SYN-ACK/RST TX, HA-safe secrets, integration evidence, and gate removal still needed |
| #1375 three-color policers | [plan-1375-three-color-policers.md](plan-1375-three-color-policers.md) | #1373 Phase 4 | Color-blind `then discard` runtime plus compatible snapshot continuity landed; sharded/packed state decision, HA/restart continuity decision, non-drop color actions, and integration/perf evidence still needed |
| #1376 port mirroring | [plan-1376-port-mirroring.md](plan-1376-port-mirroring.md) | #1373 Phase 4 | Snapshot/wire plus bounded runtime admission landed; mirror-fidelity and pressure-survival evidence still needed |
| #1377 persistent SNAT pool address selection | [plan-1377-snat-pools.md](plan-1377-snat-pools.md) | #1373 Phase 4 | Userspace-v1 selector and unusable-pool fail-closed runtime landed; persistent NAT lease reuse and allocator/exhaustion counters still needed |
| #1378 policy schedulers | [plan-1378-policy-schedulers.md](plan-1378-policy-schedulers.md) | #1373 Phase 4 | Closed by live HA artifact capture accepted by `policy_scheduler_validate.py`; no known #1378 runtime or evidence gap remains |
| #1379 dataplane events | [plan-1379-dataplane-events.md](plan-1379-dataplane-events.md) | #1373 Phase 4 | Policy-deny, screen-drop, PBR filter logs, non-PBR input/output/lo0 filter logs, cached input-log replay without filter rescans, source-disambiguated FILTER_LOG syslog, and deterministic fanout coverage landed; live cluster evidence remains if Phase 4 requires operator artifacts |
| #1380 userspace buffer/status parity | [plan-1380-userspace-buffers.md](plan-1380-userspace-buffers.md) | #1373 Phase 5 | Userspace helper-status rendering landed; final BPF-map fallback cleanup and optional true-capacity fields remain |

## Shared Dependency

#1381 is the common plumbing dependency for the blocker set. The userspace
manager no longer embeds the old `DataPlane` interface directly for the first
operator metadata surfaces, and a userspace legacy adapter owns the compatibility
boundary. Remaining Phase 3 work is to move session, telemetry, GC, and control
callers off the old BPF-shaped surface before generated bindings, loader code,
and BPF build rules can be removed. #1380 is a Phase 5 CLI/observability cleanup
blocker: it must land before BPF-map-oriented operator surfaces disappear, but
it does not block the Phase 4 forwarding-source removal gate by itself.

## Phase 1/2 Smoke Gates

Use [smoke-gates.md](smoke-gates.md) for the repeatable Phase 1/2 operator
checklist: CoS-off IPv4/IPv6 push and reverse, screen/flood baseline,
CoS-on 5200..5211 class sweeps, 6200..6211 TCP echo probes, and the
existing HA Makefile gates.

## Shared Non-Goals

- Do not remove `bpf/` in these blocker implementation PRs; that remains #1373
  Phase 4.
- Do not rewrite unrelated dataplane behavior while adding parity for the
  missing features.
- Do not use the DPDK worker as a correctness reference when it conflicts with
  the reviewed userspace-dp contract.
