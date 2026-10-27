# pkg/linkstate

Single source for the carrier-state read (#17132): `Up(attrs)` decides
whether a kernel link's `IFLA_OPERSTATE` counts as operationally up.

## Why this package exists

The predicate lived in three byte-identical copies (`pkg/cluster.LinkAttrsUp`,
`pkg/routing`'s `linkAttrsUp`, `pkg/vrrp`'s `linkAttrsUp`), and #2070 already
had to fix it in lockstep across producers. One definition here is imported by
cluster, routing, and vrrp (and, through `cluster.LinkAttrsUp`'s alias, by the
daemon/cli/grpcapi display paths).

## Rule

- `OperUp` → up.
- `OperUnknown` → fall back to the admin flag (`IFF_UP`); virtual devices and
  VLAN sub-interfaces report no independent carrier state.
- Anything else (`OperDown`, lower-layer-down, …) → down.

Never decide from `IFF_UP` alone: xpfd admin-ups every managed interface, so
the flag stays set after carrier loss and would report a cable-pulled link as
up, suppressing HA failover (#2070).

## Placement

A deliberate leaf with zero xpf imports, mirroring `pkg/netname`: every
consumer (cluster, routing, vrrp, daemon, cli, grpcapi) can import it without
a cycle.
