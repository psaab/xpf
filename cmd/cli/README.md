# cmd/cli

Standalone Junos-style CLI client. Connects to xpfd's gRPC API and runs
the same readline / tab-completion / `?`-help experience as the
daemon-local CLI.

## Entry

`main.go` parses flags, dials the gRPC API, and hands control to the
shared `pkg/cli` engine.

## Flags

- `-addr` — gRPC server address. Default `127.0.0.1:50051`.
- `-c "<command>"` — single-command, non-interactive mode. Exits with
  the command's status. Useful for scripted operations.

## Tab completion

Driven by the gRPC `Complete` RPC, which lowers the same `pkg/cmdtree`
tree the daemon uses. Adding a command in `pkg/cmdtree/tree.go` shows up
here and in the daemon-local CLI without changes here.

## Operational notes

- Output streams over gRPC. There's no separate SSH / Telnet layer —
  authentication is by gRPC peer credentials.
- `| match <pattern>` filtering is client-side; the server sends full
  output. (Junos pipes are simulated this way.)
- Some lab VMs have a stale `/usr/local/sbin/cli` that shadows the
  current `/usr/local/bin/cli` via `PATH`. If a deploy looks correct
  but the CLI behavior is stale, delete the `sbin` copy.
