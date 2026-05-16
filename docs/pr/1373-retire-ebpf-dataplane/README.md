# #1373 Retire eBPF Dataplane Blocker Plans

Status: design-plan bundle for #1373 blockers. These docs convert the
reviewed issue contracts into implementation plans for the code PRs that must
land before Phase 4 removes the legacy eBPF dataplane.

## Blocker Index

| Issue | Plan | Required before | Code PR still needed |
|---|---|---|---|
| #1374 SYN cookie flood protection | [plan-1374-syn-cookies.md](plan-1374-syn-cookies.md) | #1373 Phase 4 | Yes |
| #1375 three-color policers | [plan-1375-three-color-policers.md](plan-1375-three-color-policers.md) | #1373 Phase 4 | Yes |
| #1376 port mirroring | [plan-1376-port-mirroring.md](plan-1376-port-mirroring.md) | #1373 Phase 4 | Yes |
| #1377 persistent SNAT pool address selection | [plan-1377-snat-pools.md](plan-1377-snat-pools.md) | #1373 Phase 4 | Partly covered by #1385 |
| #1378 policy schedulers | [plan-1378-policy-schedulers.md](plan-1378-policy-schedulers.md) | #1373 Phase 4 | Yes |
| #1379 dataplane events | [plan-1379-dataplane-events.md](plan-1379-dataplane-events.md) | #1373 Phase 4 | Yes |
| #1380 userspace buffer/status parity | [plan-1380-userspace-buffers.md](plan-1380-userspace-buffers.md) | #1373 Phase 4 | Partly covered by #1386 |

## Shared Dependency

#1381 is the common plumbing dependency for the blocker set. The userspace
`Manager` still embeds the eBPF `DataPlane`, which makes capability removal,
event source selection, scheduler update dispatch, and BPF source deletion
coupled to the old map-shaped interface. The implementation PRs for #1374,
#1375, #1376, #1377, #1378, #1379, and #1380 should land after #1381 or
explicitly include the matching interface split/stub slice.

## Shared Non-Goals

- Do not remove `bpf/` in these blocker implementation PRs; that remains #1373
  Phase 4.
- Do not rewrite unrelated dataplane behavior while adding parity for the
  missing features.
- Do not use the DPDK worker as a correctness reference when it conflicts with
  the reviewed userspace-dp contract.
