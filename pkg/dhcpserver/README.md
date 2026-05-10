# pkg/dhcpserver

Manages Kea DHCPv4/v6 server config and lifecycle. Generates
`/etc/kea/kea-dhcp{4,6}.conf` from the typed config and reloads the
`kea-dhcp{4,6}-server` units via systemd.

## Entry points

- `Manager` — `dhcpserver.go`.
- `New()` — `dhcpserver.go`.
- `Apply(cfg *config.DHCPServerConfig) error` — `dhcpserver.go`. Regenerates config and restarts.
- `Clear()` — `dhcpserver.go`. Stops Kea and removes config files.
- `Lease` — `dhcpserver.go`. Surfaced to the CLI for `show dhcp
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
- Lease queries read Kea's CSV lease backends directly:
  `/var/lib/kea/kea-leases4.csv` and `kea-leases6.csv`. No control
  channel / socket call. Missing files yield an empty list, not an
  error.
