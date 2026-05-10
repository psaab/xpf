# cmd/xpfd

The xpfd daemon — the firewall control plane. Loads eBPF (or spawns the
Rust AF_XDP helper), applies compiled config to every subsystem,
handles signals, and exposes gRPC + HTTP REST + an interactive CLI.

## Entry

`main.go` parses flags and constructs `pkg/daemon.Daemon` via
`daemon.New(opts)`. The daemon instance assembles every subsystem
manager from `pkg/*` and runs them under an errgroup.

## Flags

- `-config` — config file path. Default `/etc/xpf/xpf.conf`.
- `-no-dataplane` — config-only mode (parse + validate without loading
  BPF). Useful for offline checks.
- `-api-addr` — HTTP REST listener. Default `127.0.0.1:8080`.
- `-grpc-addr` — gRPC listener. Default `127.0.0.1:50051`.
- `-debug` — verbose logging.

## Subcommands

- `xpfd version` — prints version and commit.
- `xpfd cleanup` — removes pinned BPF state and FRR-managed routes.
  Runs on uninstall.

## TTY detection

`unix.IoctlGetTermios(fd, TCGETS)` — when stdin is a real TTY, the
daemon spawns the local CLI (`pkg/cli`) on the same terminal. Service
units run without a TTY and skip that path.

## Cluster mode

`/etc/xpf/node-id` selects node (`0` or `1`); absence is standalone.
Cluster nodes pick up the bondless-RETH naming convention
(`fxp0`, `em0`, `ge-{0,7}-0-X`) and run the chassis-cluster state
machine.

## Read order

Start at `pkg/daemon/daemon.go` (`New`) for the assembly. From
there, every imported `pkg/*` has its own README.
