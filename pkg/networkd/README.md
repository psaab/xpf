# pkg/networkd

systemd-networkd file generator. Writes `.link`, `.network`, and
`.netdev` files for every xpfd-managed interface, handles MAC-based
rename, VLAN parent flagging, DHCP avoidance, and atomic file
replacement. Triggers `networkctl reload` only when files actually
changed.

## Entry points

- `Manager` — `networkd.go:51`.
- `InterfaceConfig` — `networkd.go:22`. MAC, addresses, bonding, VLAN
  parent, VRF binding, description.
- `New()` — `networkd.go:56`.
- `Apply(...)` — `networkd.go:66`.
- `Clear()` — `networkd.go:201`.
- `FindExternallyManaged()` — `networkd.go:225`. Detects networkd files
  the daemon doesn't own.

## Callers

`pkg/daemon`, `pkg/dataplane`.

## Dependencies

Standard library only.

## Naming conventions (CLAUDE.md authoritative)

- File prefix `10-xpf-` distinguishes xpf-managed files from manual
  configs. Anything else is left alone.
- Non-RETH interfaces match by `MACAddress=` — MAC is stable.
- RETH member interfaces match by `OriginalName=` (PCI kernel name)
  because the MAC alternates between physical and virtual at boot. The
  daemon's `ensureRethLinkOriginalName()` auto-fixes stale `.link` files
  that still use `MACAddress=`.
- `KeepConfiguration=static` on RETH interfaces preserves VRRP VIPs
  across `networkctl reload`.

## Gotchas

- `Apply()` only calls `networkctl reload` when files actually changed.
  This matters: a reload bounces interfaces, and an idempotent reapply
  must be cheap.
- Interfaces not in the typed config get `ActivationPolicy=always-down`
  in their `.network` file, so they stay down across reboots.
- DHCP-marked interfaces skip address reconciliation entirely — the
  daemon's DHCP client (`pkg/dhcp`) owns the address.
- VRF and tunnel interfaces created elsewhere are excluded from the
  unmanaged-interface scan via the `daemonOwned` map.
