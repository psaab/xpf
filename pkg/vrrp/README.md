# pkg/vrrp

Native VRRPv3 (RFC 5798) state machine. ~60 ms failover with 30 ms RETH
advertisements, IPv6 support, AF_PACKET RX fallback for VLAN
sub-interfaces, async GARP burst on `becomeMaster`, and sync-hold
preemption control for HA bulk session sync.

This is the package that drives chassis-cluster failover.

## Entry points

- `Manager` — `manager.go`. Owns every `Instance` goroutine, the event
  channel, and sync-hold state.
- `Instance` — `vrrp.go`. Per-RG config: interface, group ID, VIPs,
  priority, preempt, timers.
- `VRRPEvent` — `instance.go`. INIT / BACKUP / MASTER transitions.
- `NewManager()` — `manager.go`.
- `Start()` — `manager.go`.
- `Stop()` — `manager.go`.
- `UpdateInstances(cfg)` — `manager.go`.
- `ReleaseSyncHold(rg)` — `manager.go`.
- `ResignRG(rg)` — `manager.go`.

## Callers

`pkg/daemon`, `pkg/api`, `pkg/grpcapi`, `pkg/cli`.

## Dependencies

`pkg/config`, `pkg/cluster`.

## Failover timing (CLAUDE.md authoritative)

- ~60 ms with 30 ms RETH advertisements (masterDownInterval ~97 ms).
- Planned shutdown: 3× priority-0 advert burst → peer takeover ~1 ms.
- Heartbeat 200 ms, threshold 5 (1 s detection).
- Async GARP: first pair <1 ms; remaining sent at 50 ms intervals in a
  background goroutine. Critical path stays addVIPs → sendAdvert →
  emitEvent (sync), then `go sendGARP()` (async).
- Event debounce 500 ms before priority updates.
- Sync hold: VRRP starts with `preempt=false`; released after bulk
  session sync (or 10 s timeout). `preemptNowCh` triggers instant
  preemption when sync completes early.

## Sockets

- IPv4: per-instance raw socket (proto 112) plus AF_PACKET fallback for
  VLAN sub-interfaces (the kernel's raw IP doesn't reliably receive
  multicast on VLANs).
- IPv6: separate raw socket; hop limit set to 255 per RFC.

## Gotchas

- Use the **non-VIP** primary IP as source on advertisements. Sourcing
  from the VIP would self-filter peer adverts.
- RETH virtual MAC per node: `02:bf:72:CC:RR:NN`. Programmed via link
  DOWN → set MAC → link UP. This bounces all kernel addresses; VIPs are
  re-added by `ReconcileVIPs()` immediately afterwards.
- Bind retry on simultaneous boot avoids losing the master election to
  whichever node booted first.
- Event channel is bounded at 256; backpressure increments an atomic
  counter and triggers a reconciliation callback. Don't switch to an
  unbounded channel — the counter is the early warning that something
  upstream stopped draining.
