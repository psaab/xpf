# pkg/dhcpserver

Manages Kea DHCPv4/v6 server config and lifecycle. Generates
`/etc/kea/kea-dhcp{4,6}.conf` from the typed config and reloads the
`kea-dhcp{4,6}-server` units via systemd.

## Entry points

- `Manager` — `dhcpserver.go:23`.
- `New()` — `dhcpserver.go:29`.
- `Apply(cfg)` — `dhcpserver.go:34`. Regenerates config and restarts.
- `Clear()` — `dhcpserver.go:76`. Stops Kea and removes config files.
- `Lease` — `dhcpserver.go:95`. Surfaced to the CLI for `show dhcp
  server leases`.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config` only.

## Gotchas

- Config is regenerated fully on every `Apply()` (no diff). The Kea config
  schema is JSON-based, so this is cheap.
- If the typed config drops the DHCP server entirely, `Apply()` stops the
  service and removes the config file. Running Kea processes are not
  killed via SIGKILL — systemd manages the lifecycle.
- Lease queries shell out to Kea's lease-database control channel; if the
  socket is missing the call returns an empty list (not an error).
