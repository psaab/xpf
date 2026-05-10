# pkg/lldp

IEEE 802.1AB Link Layer Discovery Protocol. Sends periodic LLDP frames
out unmanaged interfaces, receives neighbor announcements, and ages
entries by TTL.

## Entry points

- `Manager` — `lldp.go:84`.
- `Neighbor` — `lldp.go:55`. Chassis ID, port ID, TTL, system name and
  description.
- `New()` — `lldp.go:92`.
- `Apply(cfg)` — `lldp.go:99`.
- `Stop()` — `lldp.go:159`.
- `Neighbors()` — `lldp.go:171`. Snapshot consumed by `show lldp
  neighbors`.

## Callers

`pkg/daemon`, `pkg/grpcapi`, `pkg/cli`.

## Dependencies

Standard library + `golang.org/x/sys/unix`. No internal `pkg/*` imports.

## Gotchas

- Uses AF_PACKET raw sockets — the daemon needs `CAP_NET_RAW`. Without
  it, send/receive silently fail and the neighbor table stays empty.
- TTL countdown is per-neighbor; expired entries auto-purge from the
  `Neighbors()` snapshot.
- The neighbor map is RWMutex-guarded. `Neighbors()` returns a copy, not
  a reference, so callers can iterate without holding the lock.
