# pkg/dhcprelay

RFC 3046 DHCPv4 relay agent. Forwards DHCP between clients on local
interfaces and remote servers, inserting Option 82 with `circuit-id` set
to the interface name.

## Entry points

- `Manager` — `relay.go`.
- `NewManager()` — `relay.go`.
- `Apply(ctx context.Context, cfg *config.DHCPRelayConfig)` — `relay.go`. Starts/stops per-interface relay
  goroutines.
- `Stats()` — `relay.go`. Per-interface counters.
- `RelayStats` — `relay.go`.

## Callers

`pkg/daemon`.

## Dependencies

`pkg/config` only.

## Gotchas

- Listens per-interface on UDP 67/68. The interface must already have an
  IPv4 address — that's what fills `giaddr`.
- Option 82 sub-option 1 (`circuit-id`) is set to the interface name; on
  the reply path it's stripped before forwarding to the client.
- Server addresses must be **literal IPs**. `Apply()` calls
  `net.ParseIP` and rejects hostnames; there is no DNS resolution
  path. To target a hostname, the operator must resolve it externally
  and put the IP in the config.
