# pkg/dhcp

DHCPv4 and DHCPv6 clients. Acquires and renews leases on firewall
interfaces and (DHCPv6) delegated prefixes. Persists DUIDs across
restarts so the same client identifier returns to the same lease.

## Entry points

- `Manager` — `dhcp.go`.
- `New(stateDir)` — `dhcp.go`.
- `Lease` — `dhcp.go`. Result of one DHCP negotiation.
- `DelegatedPrefix` — `dhcp.go`. From DHCPv6 PD.
- `Start()`, `Renew()`, `StopAll()`, `DelegatedPrefixes()`.

## Callers

`pkg/daemon` (lifecycle).

## Dependencies

External only: `github.com/insomniacslk/dhcp`, `github.com/vishvananda/netlink`.

## Gotchas

- Each DHCP client uses `context.Background()`, not the daemon context.
  On graceful SIGTERM the daemon exits without calling `StopAll()`,
  intentionally leaving the lease in place so the next daemon process
  reuses it (no DAD storm, no DHCP renew at startup).
- The lease-change callback is debounced 2 seconds to avoid floods during
  config apply.
- DUID is cached per-interface in the state directory with type hints
  (`duid-ll`, `duid-llt`).
- The DHCP client owns the address. `pkg/networkd` deliberately skips
  address reconciliation on DHCP-marked interfaces.
- DHCP-learned default routes go into FRR with admin distance 200 — lower
  priority than static routes, so a configured static default wins.
