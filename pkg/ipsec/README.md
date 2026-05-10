# pkg/ipsec

strongSwan integration. Generates `swanctl.conf` from the typed config
(IKE proposals, traffic selectors, DPD profiles, NAT traversal, XFRM
interface IDs) and queries SA/SP state via `swanctl`.

## Entry points

- `Manager` — `ipsec.go`.
- `New()` — `ipsec.go`. Default swanctl conf dir
  `/etc/swanctl/conf.d`.
- `Apply(cfg)` — `ipsec.go`. Generate config and reload strongSwan.
- `Clear()` — `ipsec.go`.
- `SAStatus`, `TerminateAllSAs`, `InitiateConnection`.

## Callers

`pkg/daemon` (lifecycle), `pkg/grpcapi` (show / request commands).

## Dependencies

`pkg/config` only.

## File layout

- Writes `/etc/swanctl/conf.d/xpf.conf` with mode 0600.
- Reloads via `swanctl --reload`.

## Gotchas

- IKE version negotiation supports v1-only, v2-only, or dual (default).
  Aggressive mode is opt-in.
- NAT traversal modes: `disable`, `force`, `enable` (auto-detect).
  `NoNATTraversal` is a legacy flag retained for older configs.
- Traffic selectors are auto-derived from the policy source / destination
  prefixes when not given explicitly. Mixing explicit and derived
  selectors is supported but the explicit set wins.
- DPD (dead-peer detection) profiles auto-generate from IKE/ESP
  lifetimes. Operators can override with explicit `dead-peer-detection
  delay/timeout`.
- XFRM interface ID is derived from the bind-interface name via
  `xfrmiIfID()`. The same name → same numeric ID across reboots — don't
  rename a bind interface without expecting a reset of the SAs that ride
  it.
