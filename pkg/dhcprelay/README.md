# pkg/dhcprelay

RFC 3046 DHCPv4 relay agent. Forwards DHCP between clients on local
interfaces and remote servers, inserting Option 82 with `circuit-id` set
to the interface name.

## Entry points

- `Manager` — `relay.go:49`.
- `NewManager()` — `relay.go:55`.
- `Apply(cfg)` — `relay.go:63`. Starts/stops per-interface relay
  goroutines.
- `Stats()` — `relay.go:131`. Per-interface counters.
- `RelayStats` — `relay.go:33`.

## Callers

`pkg/daemon`.

## Dependencies

`pkg/config` only.

## Gotchas

- Listens per-interface on UDP 67/68. The interface must already have an
  IPv4 address — that's what fills `giaddr`.
- Option 82 sub-option 1 (`circuit-id`) is set to the interface name; on
  the reply path it's stripped before forwarding to the client.
- Server addresses are resolved once at `Apply()` time; if a server's DNS
  changes you need a config reload.
