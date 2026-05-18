# pkg/cluster

Chassis-cluster HA state machine. Owns node state (Primary, Secondary,
SecondaryHold, Lost, Disabled), redundancy-group election, readiness
gates, manual failover, and the callbacks that fire session/config/IPsec
sync.

## Entry points

- `NodeState` — `cluster.go`. State enum constants.
- `RedundancyGroupState` — `cluster.go`. Per-RG state with
  readiness/transferReady tracking.
- `Manager` — `cluster.go`. Election logic, weight calculation, event
  history.
- `ClusterEvent` — `cluster.go`. State-change notifications. The
  primary consumer of the `Manager.Events()` channel is
  `pkg/daemon/daemon_ha.go`, which fans events out (HA sync, status
  publish, etc.). `pkg/cluster/reth.go::HandleStateChange` is a
  state-handler method, not the event-channel consumer.
- `SessionSync` — `sync.go`, `sync_conn.go`, `sync_bulk.go`. HA session
  replication. Legacy constructors still accept a transitional
  `dataplane.DataPlane`, but they immediately adapt it to `SessionStore` and
  `Telemetry`. The receive, sweep, bulk export, and stale-reconcile paths must
  stay on those runtime-domain interfaces.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`, `pkg/vrrp`.

## Dependencies

`config`, `dataplane`.

## Failover timing (CLAUDE.md authoritative)

- ~60 ms with default 30 ms VRRP advertisements (masterDownInterval ~97 ms).
- Planned shutdown: burst of 3× priority-0 advertisements; peer takes over
  in ~1 ms.
- Failback: ~130 ms (daemon startup + BPF load + sync hold release).
- Heartbeat: 200 ms interval, threshold 5 (1 s detection).
- Event debounce 500 ms before priority updates fire.

## Gotchas

- `Ready` and `TransferReady` are different gates. `Ready` allows VRRP to
  participate in election; `TransferReady` is the stricter gate for
  explicit operator-initiated `request chassis cluster failover`.
- `TakeoverHoldTime` adds extra delay before election when this node would
  immediately preempt. Used to avoid election thrash on simultaneous boot.
- HA delete-sync callbacks fire from the GC loop. They must not block, and
  must log at `slog.Debug` — earlier `slog.Info` flooded at 15 req/s and
  drowned out real diagnostics (per CLAUDE.md logging rules).
- Session-sync key-only delete messages use `SessionStore.DeleteWithCompanions*`.
  Bulk stale reconciliation must use the known-value batch delete path through
  `SessionStore.ReconcileClusterBulk`, which deletes with the iterator's
  `(key,value)` snapshot. Reverse-session, DNAT/DNATv6, and persistent-NAT
  side effects are backend-owned; do not add local map cleanup in
  `pkg/cluster`.
- Dual-active overlap is intentional: primary sets `rg_active=true`
  immediately on becoming master; secondary defers `rg_active=false` until
  it sees the VRRP BACKUP event. Brief overlap, never both inactive.
