# cmd/xpfd

The xpfd daemon — the firewall control plane. Starts the configured
dataplane, applies compiled config to every subsystem, handles signals,
and exposes gRPC + HTTP REST + an interactive CLI.

## Entry

`main.go` classifies the command, parses daemon arguments with the private
`parseDaemonArgs` flag set, and constructs `pkg/daemon.Daemon` through
`runDaemon` only after parsing and semantic validation succeed. The daemon
instance assembles every subsystem manager from `pkg/*` and runs them under an
errgroup. A typed daemon result keeps help, flag syntax, positional remainder,
semantic, construction, and runtime failures distinct so `main` owns each
diagnostic and exit status exactly once.

`main()` first routes on `classifyCommand(os.Args)` — the pure,
side-effect-free SSOT for the top-level subcommand decision (which
subcommand runs for a given argv; `cmdDaemon` is the fall-through that passes
exactly `os.Args[1:]` to `parseDaemonArgs`). A subcommand is recognized only as
the first argument. Daemon mode accepts flags only: every positional remainder
is rejected before logging or daemon construction, and a bare `--` is accepted
only when no token follows it. `xpfd upgrade` then routes on
`upgradeArgsSelectKernel` (binary cut-over vs `upgrade kernel`). Both
routing decisions and every subcommand arg parser
(`parseUpgradeArgs`, `parseSeedRuntimeArgs`,
`parsePublishGenerationArgs`, `parseCleanupArgs`,
`validateKernelVerbArgs`) are unit-testable without `os.Exit` or the
real upgrade/cleanup side effects (`dispatch_test.go`,
`upgrade_args_4869_test.go`, `leftover_args_5322_test.go`).

## Flags

- `-config` — config file path. Default `/etc/xpf/xpf.conf`.
- `-no-dataplane` — config-only mode (parse + validate without starting
  the dataplane). Useful for offline checks.
- `-api-addr` — HTTP REST listener. Default `127.0.0.1:8080`.
- `-grpc-addr` — gRPC listener. Default `127.0.0.1:50051`.
- `-debug` — verbose logging.
- `-cold-path-sample-mask` — powers-of-two-minus-one sampling mask. Default
  `0xff`; an explicitly authored value is forwarded to the userspace dataplane.
- `-enable-cold-path-1-in-1-sampling` — explicit bounded-benchmark override for
  one-in-one cold-path sampling. Never use in production.

## Subcommands

- `xpfd version` — prints version and commit.
- `xpfd protocol-versions` — prints embedded HA, session-sync, and
  config-database protocol compatibility values.
- `xpfd cleanup` — closes kernel transit, removes pinned BPF state, and clears
  FRR-managed routes. Runs on uninstall.
- `xpfd upgrade` — runs the verified binary or kernel upgrade workflow.
- `xpfd seed-runtime` — seeds the versioned runtime layout on first install.
- `xpfd publish-generation` — publishes a complete staged binary generation.
- `xpfd verify-dataplane` — verifies the embedded userspace shim without
  touching production dataplane state.
- `xpfd check-config <config-file>` — runs strict config validation and the
  device-map management-stranding preflight, then prints any non-fatal compile
  advisories as `warning:` lines while retaining a successful exit status.
- `xpfd export-config <output-file>` — writes the CURRENT active config DB as
  hierarchical day-0 text to a 0600 file for image-replace upgrades. Refuses
  stdout, a missing/empty active config DB, or an invalid output path.
- `xpfd transit-barrier close` — installs the inet and bridge forward-hook DROP
  barrier without loading configuration or taking the daemon lock. The early
  boot unit runs it before `systemd-networkd.service`.
- `xpfd transit-barrier remove` — removes both transit-barrier tables so package
  removal can release the boot/shutdown fence.
- A kernel without bridge nf_tables reports degraded success with a warning
  when the inet barrier is active; inet failures and real bridge errors fail.

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
