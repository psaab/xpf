# pkg/frr

FRR (FRRouting) integration. Generates a managed section inside
`/etc/frr/frr.conf` from the typed config (static routes, OSPF, BGP,
ISIS, RIP, BFD profiles, multi-VRF instances) and queries protocol state
via `vtysh`.

This package is the only place in the codebase that's allowed to touch
kernel routes — and it doesn't, directly. It writes config and reloads
FRR, which then owns the kernel route table.

## Entry points

- `Manager` — `frr.go`.
- `New()` — `frr.go`. Defaults to `/etc/frr/frr.conf`.
- `ApplyFull(cfg)` — apply full config (idempotent diff against on-disk).
- `FullConfig` — `frr.go`.
- `InstanceConfig` — `frr.go`. One per-VRF.
- State queries (vtysh): `GetRIPRoutes` (frr.go), `GetISISAdjacency`,
  `GetBGPNeighbors`, …

## Callers

`pkg/daemon` (lifecycle), `pkg/grpcapi` (show commands).

## Dependencies

`pkg/config` only.

## Managed-section markers

`! BEGIN BPFRX MANAGED CONFIG` … `! END BPFRX MANAGED CONFIG`. User-edited
content **outside** the markers is preserved across `ApplyFull`. Don't
move or rename the markers — they're literal strings.

## Gotchas

- Static routes have RETH names (`reth0`) but FRR wants the physical
  member name in cluster mode. The package translates via `RethMap` from
  the typed config.
- IPv6 next-hops without an explicit interface require `IPv6NextHopInterfaces`
  for link-local resolution — link-local addresses alone are ambiguous to
  FRR.
- In cluster mode the package emits a blackhole default at admin distance
  250 so traffic to the active fabric peer survives a brief
  active/active overlap.
- `vtysh -c` is run synchronously in batch mode for state queries. There
  is no streaming; long output is buffered.
