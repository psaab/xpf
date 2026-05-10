# pkg/daemon

Daemon lifecycle and orchestration. Loads eBPF, applies compiled config
to all subsystems (routing, NAT, DHCP, cluster, …), handles signals
(SIGHUP reload, SIGTERM shutdown), and wires the commit-atomicity
semaphore (#846) so `Store.Commit()` and `applyConfig()` always run
together.

This is the package `cmd/xpfd` instantiates. It depends on essentially
every other internal package.

## Entry points

- `Daemon` — `daemon.go`.
- `Options` — `daemon.go`. `ConfigPath`, `NoDataplane`, `APIAddr`,
  `GRPCAddr`, `Version`.
- `New(opts) *Daemon` — `daemon.go`.
- `CompileHealth` — `daemon.go`. Snapshot of the most recent compile
  outcome; `pkg/api` consumes it for the `/health` endpoint.

## Cluster mode

Detected by the presence of `/etc/xpf/node-id` (contents `0` or `1`).
Absent → standalone. Cluster mode triggers the bondless-RETH naming
convention (`fxp0`, `em0`, `ge-{0,7}-0-X`).

## Interface management

`enumerateAndRenameInterfaces()` runs at startup (in `linksetup.go`),
writes `.link` files for every PCI-enumerated NIC, and assigns vSRX names
based on PCI bus order plus the cluster node ID. RETH members match by
`OriginalName=` (PCI kernel name), not `MACAddress=` — the MAC alternates
between physical and virtual at boot, and `ensureRethLinkOriginalName()`
auto-fixes stale `.link` files.

Any interface not declared in the active config is brought down and given
`ActivationPolicy=always-down` in networkd.

## Notable gotchas

- ISSU (in-service software upgrade) preserves sessions across the upgrade
  by handing the BPF map FDs to the new daemon and timing the cutover
  against HA failover.
- CoS configuration is wiped on every cluster deploy. Re-apply with
  `test/incus/apply-cos-config.sh` after `cluster-setup.sh deploy`. (See
  CLAUDE.md.)
- `commitFn` and `commitConfirmedFn` are passed to `pkg/cli` and
  `pkg/grpcapi`; they hold the apply semaphore across the commit + apply
  pair so concurrent committers serialize.
- FRR reload runs with a 15 s context timeout to keep `systemctl reload
  frr` from hanging. The systemd unit has `TimeoutStopSec=20` as a safety
  net.
