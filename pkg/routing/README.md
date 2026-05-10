# pkg/routing

Manages static routes, GRE tunnels, VRFs, XFRM interfaces, and tunnel
keepalive probes via netlink. Tracks link state for monitored interfaces
and exposes per-tunnel RTT/loss metrics for weight-based failover.

This package owns netlink object lifecycles. FRR (`pkg/frr`) owns the
kernel route table; this package owns the *interfaces* routes hang off
of.

## Entry points

- `Manager` — `routing.go`.
- `VRFSpec` — `routing.go`.
- `KeepaliveState` — `routing.go`. Per-tunnel probe status.
- `TunnelStatus` — `routing.go`.
- `RouteEntry` — `routing.go`.
- `InterfaceMonitorStatus` — `routing.go`.
- `New()` — `routing.go`.
- `ApplyTunnels(cfg)` — `routing.go`.
- `ReconcileVRFs(cfg)` — `routing.go`.
- `ApplyXfrmi(cfg)` — `routing.go`.

## Callers

`pkg/daemon`, `pkg/api`, `pkg/grpcapi`, `pkg/cli`.

## Dependencies

`pkg/config` only.

## ip-rule priorities

- `100–199`: next-table inter-VRF leaking (static routes with
  `next-table` directive). `nextTableRulePriority` in `routing.go`.
- `31000–31999`: PBR (firewall-filter `routing-instance` action).
  `pbrRulePriority` in `routing.go`.
- `33000–33099`: rib-group inter-VRF leaking (`from all lookup
  <table>`).
- main table at `32766`. The next-table range sits **before** main
  (lower priority value = higher priority). PBR sits before main as
  well; rib-group sits after.

## Gotchas

- #848: `ifaceMu` serializes tunnel/xfrmi/bond slice access. Long-running
  reads snapshot under the lock and iterate the copy lock-free.
- `vrfsMu` is a separate lock. `ReconcileVRFs` holds it for the entire
  netlink reconciliation; it isn't re-entrant.
- Keepalive runner goroutines drain on the `done` channel before the
  netlink handle is closed. Closing the handle while a goroutine still
  holds it would be a use-after-close.
- Static routes go through `pkg/frr`, not this package. The "next-table"
  and "rib-group" leaking modes go through `ip rule` (here), not FRR.
- RPM probes that need VRF binding use `SO_BINDTODEVICE` on the VRF
  device, not on the destination interface.
