# xpf Testing Documentation

> Deprecation notice (#1373): the legacy eBPF dataplane is being retired. New
> dataplane validation should use the userspace AF_XDP cluster unless a staged
> retirement phase calls for explicit legacy regression coverage. Phase 0 removes
> no BPF source or test target.

Comprehensive test plans and validation procedures for both the legacy eBPF
dataplane and the userspace AF_XDP dataplane.

## Test Categories

| Document | Scope | Automation |
|----------|-------|------------|
| [unit-tests.md](unit-tests.md) | Go + Rust unit tests | `make test` + `cargo test` |
| [standalone-vm.md](standalone-vm.md) | Single-VM forwarding, NAT, policy | `make test-deploy` |
| [ha-cluster.md](ha-cluster.md) | HA failover, crash recovery, session sync | `make test-failover` |
| [failover-testing.md](failover-testing.md) | End-to-end failover-only runbook across userspace and eBPF HA clusters | Manual + scripts |
| [manual-failover-transfer-commit-validation.md](manual-failover-transfer-commit-validation.md) | Live validation of sync-channel manual failover completion after `#397` | Manual |
| [userspace-fabric-failover.md](userspace-fabric-failover.md) | Userspace RG move across fabric, failover hardening, artifact interpretation | `scripts/userspace-ha-failover-validation.sh` |
| [userspace-dataplane.md](userspace-dataplane.md) | AF_XDP forwarding, cold start, neighbor resolution | Manual + scripts |
| [native-gre.md](native-gre.md) | Native GRE transit, failover, host-origin validation | `scripts/userspace-native-gre-validation.sh` |
| [performance.md](performance.md) | Throughput, latency, perf profiling | `scripts/userspace-perf-compare.sh` |
| [regression-checklist.md](regression-checklist.md) | Pre-commit validation checklist | Manual |

## Quick Reference

```bash
# Unit tests (must pass before any commit)
make test                          # 880+ Go tests, 26 packages
cd userspace-dp && cargo test      # 356 Rust tests

# Standalone VM
make test-deploy                   # Build + deploy to xpf-fw
make test-ssh                      # Shell into VM

# HA Cluster (eBPF)
make cluster-deploy                # Deploy to xpf-fw0 + xpf-fw1
make test-failover                 # Reboot fw0 during iperf3
make test-ha-crash                 # Force-stop/daemon-stop/multi-cycle

# Userspace HA Cluster
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
scripts/userspace-ha-validation.sh           # Full validation suite
scripts/userspace-ha-failover-validation.sh  # Failover-specific
scripts/userspace-native-gre-validation.sh   # Native GRE transit/failover
```

For userspace RG-move failover specifically, use
[userspace-fabric-failover.md](userspace-fabric-failover.md) as the reference
for the hardened acceptance bar, stale-owner fabric workflow, and artifact
interpretation.

## Operational Notes

- `test/incus/cluster-setup.sh deploy all` builds, pushes, and restarts
  `xpfd` in a rolling sequence. Do not add an extra manual restart unless you
  are explicitly testing restart behavior.
- After a reboot of the remote `loss` host, repair VF trust/VLAN state before
  drawing any dataplane conclusions:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs

BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs
```

- The `.200` / `::200` throughput targets are not local Incus containers. When
  you need captures from the remote endpoint, use the gRPC capture service
  documented in `~/README.md` (`capture-client` / `grpcurl`), not ad-hoc
  `tcpdump` assumptions on unrelated lab hosts.
- For userspace split-RG failover, `monitor interface <fabric-parent>` is now a
  required live-debug tool, not just a convenience command. It exposes the
  userspace binding state, queue readiness, direct/copy/in-place TX, misses,
  policy denies, binding errors, and recent exceptions for a single interface.
  Use it during RG moves to distinguish:
  - "traffic never hit the old owner"
  - "traffic hit the old owner and redirected across fabric"
  - "traffic hit the old owner but died on the copy-mode fabric path"

## Test Environment Topology

See [CLAUDE.md](../CLAUDE.md) for full network topology details.

### Standalone VM (`xpf-fw`)
- Virtio interfaces: fxp0 (mgmt), ge-0-0-0 (trust), ge-0-0-1 (untrust), ge-0-0-2 (dmz)
- i40e PCI passthrough: ge-0-0-3 (wan), ge-0-0-4 (loss)
- Test containers: trust-host, untrust-host, dmz-host

### eBPF HA Cluster (`xpf-fw0`, `xpf-fw1`)
- Two VMs with VRRP, fabric link, session sync
- `cluster-lan-host` container for traffic generation
- Config: `docs/ha-cluster-loss.conf`

### Userspace HA Cluster (`xpf-userspace-fw0`, `xpf-userspace-fw1`)
- On remote `loss` host with Mellanox SR-IOV VFs (zero-copy AF_XDP)
- `cluster-userspace-host` container
- Config: `docs/ha-cluster-userspace.conf`
- Test targets: 172.16.80.200 (IPv4), 2001:559:8585:80::200 (IPv6)
- Native GRE target: 10.255.192.41
