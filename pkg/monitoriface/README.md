# pkg/monitoriface

Interface-statistics snapshot reader and renderer. Reads kernel counters
plus userspace-dataplane counters (XSK bindings, TX packets, kernel
drops) and renders the `monitor interface` view in any of four modes:
packets, bytes, delta, rate.

## Entry points

- `Snapshot` — `monitor.go:35`. Kernel counters (Rx/TxBytes, errors,
  collisions, etc.).
- `UserspaceSnapshot` — `monitor.go:53`. Per-binding XSK stats.
- `CounterReader` interface — `monitor.go:18`. Abstracts BPF map access
  so tests can inject a fake.
- `ReadSnapshot()` — `monitor.go:465`.
- `RenderSingleInterface()` — `monitor.go:536`.
- `RenderTrafficSummary()` — `monitor.go:714`.

## Callers

`pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`, `pkg/dataplane`, `pkg/dataplane/userspace`.

## Gotchas

- Delta and rate modes need a baseline snapshot. The caller is
  responsible for sampling on a consistent interval; this package does
  no scheduling itself.
- Userspace snapshots require a `StatusReader` callback to the dataplane
  process. With the eBPF backend, the userspace half is empty.
- VLAN sub-interfaces resolve to their physical parent via
  `ResolvePhysicalParent` so per-NIC summary rows aren't double-counted.
