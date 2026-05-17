# Regression Checklist

Pre-commit validation checklist. Check the boxes that apply to your change.

## Always Required

- [ ] `make test` — all Go tests pass (880+ tests, 26 packages)
- [ ] `cd userspace-dp && cargo test` — all Rust tests pass (356 tests)
- [ ] `make build` — Go daemon compiles
- [ ] `make build-ctl` — CLI client compiles

## If You Changed Rust Userspace Code (`userspace-dp/`)

- [ ] `cargo build --release` — release build succeeds
- [ ] Deploy to loss userspace cluster: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./test/incus/cluster-setup.sh deploy all`
- [ ] `RUNS=1 DURATION=5 PARALLEL=4 scripts/userspace-ha-validation.sh` — passes
- [ ] `scripts/userspace-ha-failover-validation.sh --duration 60 --parallel 4` — no zero-throughput collapse and external IPv4/IPv6 stay reachable during failover/failback
- [ ] The failover artifacts show positive fabric TX delta on the old owner for each RG move
- [ ] Fresh standby WAN deltas stay flat during stale-owner fabric redirect checks
- [ ] The failover artifacts keep session/neighbor/route/policy deltas within threshold for each RG move
- [ ] The old owner stays `Enabled=true`, `Forwarding armed=true`, and `Ready bindings > 0` through failover/failback
- [ ] Manual IPv4 + IPv6 `iperf3 -P 8` from `cluster-userspace-host` stay stable (no stream stuck at 0)
- [ ] If the change affects split-RG failover or fabric forwarding, run at least one manual stale-owner fabric case:
  - `RG1` moved to `node0`
  - `cluster-userspace-host -> 172.16.80.200`
  - `monitor interface ge-7-0-0` on `node1`
  - confirm traffic crosses fabric and does not egress standby WAN
- [ ] If the host rebooted recently: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./test/incus/cluster-setup.sh refresh-vfs`
- [ ] Review [userspace-fabric-failover.md](userspace-fabric-failover.md) if the change affects HA redirect, session sync, standby arming, or failover recovery quality

## If You Changed XDP Shim (`userspace-xdp/`)

- [ ] `bash pkg/dataplane/build-userspace-xdp.sh` — BPF object compiles and embedded object is refreshed
- [ ] `make build` — Go daemon embeds new XDP object
- [ ] Deploy and check: `journalctl -u xpfd | grep "stack.*too large"` — NO stack overflow
- [ ] Cluster comes up: `show chassis cluster status` — both nodes have primary/secondary

## If You Changed Cluster / VRRP / Session Sync

- [ ] `make cluster-deploy` — deploy to canonical loss userspace cluster
- [ ] `make test-failover` — **MANDATORY** per CLAUDE.md
- [ ] `make test-ha-crash` — crash recovery works
- [ ] Session sync: `show security flow session` on secondary shows synced sessions

## If You Changed Forwarding / NAT / Policy

- [ ] `make test-deploy` — deploy to standalone VM
- [ ] `./test/incus/test-connectivity.sh` — all zones can communicate per policy
- [ ] SNAT flows show correct translated source
- [ ] DNAT flows reach internal server

## If You Changed Config Parser

- [ ] Run flat `set` syntax tests: `go test -run TestSet ./pkg/config/...`
- [ ] Run hierarchical tests: `go test -run TestParse ./pkg/config/...`
- [ ] Test both `load override` and `load merge` paths
- [ ] Verify `show | display set` round-trips correctly

## If You Changed FRR / Routing

- [ ] `vtysh -c "show ip route"` — routes correct
- [ ] VRF isolation: traffic in one VRF doesn't leak to another
- [ ] Default route via DHCP: admin distance 200

## If You Changed RA / IPv6

- [ ] After restart: host gets IPv6 default route via RA within 30s
- [ ] `ip -6 route show default` on host — exists via stable link-local
- [ ] Ping firewall VIP: `ping6 2001:559:8585:ef00::1` — works

## Performance Regression Check

Run before and after:
```bash
scripts/userspace-perf-compare.sh --duration 10 --parallel 8
```

**Red flag**: > 5% sustained throughput drop.

## If You Changed Native GRE / Tunnel Handoff

- [ ] `scripts/userspace-native-gre-validation.sh --iperf --udp --traceroute` — steady-state passes
- [ ] `scripts/userspace-native-gre-validation.sh --failover --iperf --udp --traceroute` — failover path passes
- [ ] If host-origin traffic is affected: rerun with `GRE_VALIDATE_HOST_PROBES=1`
- [ ] Review [native-gre.md](native-gre.md) if the change affects tunnel ownership, host-origin handoff, or GRE failover behavior

## Commit Message Convention

```
type(scope): short description

Longer description if needed.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`
Scopes: `afxdp`, `xdp-shim`, `cluster`, `vrrp`, `config`, `daemon`, `ra`
