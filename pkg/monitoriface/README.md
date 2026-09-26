# pkg/monitoriface

Interface-statistics snapshot reader and renderer. Reads kernel counters
plus userspace-dataplane counters (XSK bindings, TX packets, kernel
drops) and renders the `monitor interface` view in any of four modes:
packets, bytes, delta, rate.

## Entry points

- `Snapshot` — `monitor.go`. Kernel counters (Rx/TxBytes, errors,
  collisions, etc.).
- `UserspaceSnapshot` — `monitor.go`. Per-binding XSK stats.
- `RuntimeDataPlane` / `CounterReader` interface — `monitor.go`.
  Abstracts monitor-interface counter reads so callers adapt broader
  dataplanes at their package boundary and tests can inject a fake.
- `ReadSnapshot(counterReader CounterReader, statusReader StatusReader, kernelName string) (Snapshot, error)` — `monitor.go`.
- `ResetOnDeviceChange(displayName string, trackedKernel *string, newKernel string, prev, baseline **Snapshot) string` — `monitor.go`. Resets single-interface rate/delta baselines and returns a persistent annotation when the kernel device changes.
- `RenderSingleInterface(w io.Writer, hostname, displayName, kernelName string, snap, prev, baseline *Snapshot, startTime time.Time, deviceNote string)` — `monitor.go`.
- `RenderTrafficSummary(w io.Writer, hostname string, names []string, kernelNames map[string]string, snaps, prevSnaps map[string]*Snapshot, mode SummaryMode, startTime time.Time)` — `monitor.go`.

## Callers

`pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`, `pkg/dataplane/userspace`.

## Gotchas

- Delta and rate modes need a baseline snapshot. The caller is
  responsible for sampling on a consistent interval; this package does
  no scheduling itself.
- Userspace snapshots require a `StatusReader` callback to the dataplane
  process. With the eBPF backend, the userspace half is empty.
- The `StatusReader` returns the whole-process status, so `ReadSnapshot`
  invokes it once per interface. A caller that reads many interfaces per
  tick — or fans one poll out to many concurrent subscribers — MUST
  coalesce the `StatusReader` (share one snapshot per tick) or it issues
  O(interfaces*subscribers) control-socket queries and contends with
  session installs. `pkg/grpcapi`'s `MonitorInterface` streaming path
  does this with a shared, short-TTL status cache (#5707); pass that
  cached reader in as the `StatusReader` rather than a raw per-call
  `Status()`.
- VLAN sub-interfaces resolve to their physical parent via
  `ResolvePhysicalParent` so per-NIC summary rows aren't double-counted.
