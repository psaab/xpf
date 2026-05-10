# pkg/cli

Interactive Junos-style CLI: readline-driven REPL with tab completion, `?`
help, prefix matching, `| match` filtering, and command history. Used by
both the daemon-local CLI (xpfd in TTY mode) and the remote CLI
(`cmd/cli`) once it has a gRPC connection.

## Entry points

- `CLI` — `cli.go`. The REPL engine.
- `New(...)` — `cli.go`. Takes ~10 injected managers (configstore,
  dataplane, cluster, frr, dhcp, …). The package has no globals.
- The readline command tree is compiled from `pkg/cmdtree` at REPL
  start; add a new command in `pkg/cmdtree/tree.go` and it shows up
  here, in the remote CLI, and in gRPC tab completion automatically.
- Per-injection setters: `SetForwardingSampler`, `SetRPMResultsFn`,
  `SetFeedsFn`, `SetLLDPNeighborsFn`, `SetVRRPManager`,
  `SetApplyConfigFn`, `SetCommitFns`, …. All on `*CLI`.

## Callers

`cmd/cli` (remote client), `cmd/xpfd` (when stdin is a TTY).

## Dependencies

`appid`, `cluster`, `cmdtree`, `config`, `configstore`, `dataplane`,
`dhcp`, `dhcprelay`, `feeds`, `frr`, `ipsec`, `lldp`, `logging`, `routing`,
`rpm`, `vrrp`.

## Gotchas

- TTY detection uses `unix.IoctlGetTermios(fd, TCGETS)`, **not**
  `os.ModeCharDevice` — `/dev/null` matches `ModeCharDevice` and would
  trick the latter into starting an interactive session in a systemd unit.
- Commits prefer the daemon's atomicity primitive: `commitFn` and
  `commitConfirmedFn` hold the apply semaphore across `store.Commit()` and
  the dataplane apply. This serializes CLI commits with HTTP/gRPC
  commits (#846). Falls back to `store.Commit()` + `applyConfigFn` only
  when the daemon hookups are absent (test/standalone).
- `fwdSampler` (forwarding CPU stats) can be `nil` — every show handler
  null-checks it.
