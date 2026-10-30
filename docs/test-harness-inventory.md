# Test harness inventory — what we can run, and on which cluster

**Date:** 2026-10-21
**Companion to:** [incus-tcp-udp-plan.md](incus-tcp-udp-plan.md) (the twin `tcp:`/`udp:`
userspace test-firewall setup). That plan's §6 defines validation gates
V0–V7; this doc lists every harness available to execute them, plus the
wider harness estate the plan inherited from the `loss:` cluster.
**Scope note:** repo paths are relative to the watermelon-xpf checkout.
Nothing in this doc was executed to produce it — entries are from
script headers, the `Makefile`, and the plan's §1.1/§5/§6. Where a
harness's state on the new `tcp`/`udp` clusters is known, it is marked.

## How harnesses are parameterised

Almost everything live-fire takes a **cluster env file** and runs
against whatever cluster it names — the same harness serves `loss:`,
`tcp:`, and `udp:`:

| Variable | Used by | Default |
| --- | --- | --- |
| `CLUSTER_ENV=<file>` | `Makefile` cluster/test targets | `test/incus/loss-userspace-cluster.env` |
| `BPFRX_CLUSTER_ENV=<file>` | `test/incus/*.sh`, `scripts/userspace-*.sh` | `test/incus/loss-userspace-cluster.env` |

Cluster envs that exist:

| Env file | Remote | Nodes | Status |
| --- | --- | --- | --- |
| `test/incus/loss-userspace-cluster.env` | `loss:` | `xpf-userspace-fw0/1`, `cluster-userspace-host`, `xpf-mouse-target` | Reference cluster; all harnesses below were built against it |
| `test/incus/loss-cluster.env` | `loss:` | kernel-dataplane cluster | Legacy/non-userspace variant |
| `test/incus/tcp-userspace-cluster.env` | `tcp:` | `xpf-tcp-fw0/1`, `cluster-tcp-host`, `xpf-tcp-target` | Live (attempt 1); bridge fabric fallback |
| `test/incus/udp-userspace-cluster.env` | `udp:` | `xpf-udp-fw0/1`, `cluster-udp-host`, `xpf-udp-target` | Live (attempt 1); bridge fabric fallback |
| `test/incus/wg-interop.env` | `loss:` | `xpf-wg-peer` + cluster | WireGuard interop only |

**Shared-cluster discipline.** One global cluster lock serialises
destructive work across all clusters/agents. Destructive harnesses run
inside the lock cell (`test/incus/with-cluster.sh`, `cluster-cell.sh`);
a standalone invocation queues behind a held lock rather than failing.
Live runs append one JSON verdict row per gate to
`test/results/ledger.d/` via `test/incus/harness-result.sh` (verdict is
a string, never just an exit code); `make harness-compare`,
`harness-coverage`, and `harness-ledger-lint` read the ledger back.

## 1. Cluster lifecycle & deployment

| Harness | Invocation | What it does |
| --- | --- | --- |
| Cluster bring-up | `make CLUSTER_ENV=<env> cluster-init` / `cluster-create` / `cluster-start` / `cluster-stop` / `cluster-destroy` | Provisions the two FW VMs, generator, and target per the env (SR-IOV VFs, bridges, profiles) |
| Deploy + gate | `make CLUSTER_ENV=<env> cluster-deploy` / `cluster-deploy-and-gate` | Builds and rolls xpf onto both nodes; `-and-gate` adds the post-deploy smoke |
| Deploy engine | `test/incus/cluster-setup.sh <subcommand>` (`BPFRX_CLUSTER_ENV=<env>`) | The script under the make targets: create/deploy/validate for the two-VM chassis cluster (fxp0/em0/fabric + LAN container) |
| Inspect | `make CLUSTER_ENV=<env> cluster-status` / `cluster-ssh` / `cluster-logs` | Instance state, shell, journal access |
| Target services | `test/incus/target-services.sh up|status` (`TARGET_V4=… INCUS_REMOTE=…`) | The one place that knows the WAN-target service grid: iperf3 `5200-5211` + TCP echo `6200-6211`, port→class map in `test/incus/cos-iperf-config.set`. **Known gap: grid not yet installed on the `tcp`/`udp` targets — ad-hoc one-off iperf servers were used in attempt 1** |
| Mouse target | `make mouse-target-up` / `mouse-target-status` / `mouse-target-destroy` | Manages the `loss:` WAN target instance used by latency/CoS cells |

## 2. Connectivity & forwarding behaviour (wire suite)

All run via `make CLUSTER_ENV=<env> test-<name>` and record to the
ledger. Most also have a `*-lib` selftest target (hermetic, no cluster);
`test-connectivity`, `test-restart-connectivity`, and
`test-wire-properties` have none.

| Gate target | Script | Proves |
| --- | --- | --- |
| `test-connectivity` | `test/incus/test-connectivity.sh` | End-to-end smoke: xpfd health, same-subnet and cross-zone ping v4/v6, VRF-aware |
| `test-restart-connectivity` | `test/incus/test-restart-connectivity.sh` | Connectivity survives daemon/VM restart |
| `test-wire-properties` | `test/incus/test-wire-properties.sh` | On-the-wire frame properties of forwarded traffic |
| `test-wire-zone-matrix` | `test/incus/wire-zone-matrix.sh` | Zone-pair allow/deny matrix (trust→untrust ALLOW, untrust→trust BLOCK, trust→trust ALLOW) |
| `test-wire-policy-deny` | `test/incus/wire-policy-deny.sh` | Policy deny actually drops, with counters |
| `test-wire-hostinbound-deny` | `test/incus/wire-hostinbound-deny.sh` | Host-inbound traffic denied where not permitted |
| `test-host-inbound` (+`-failover`) | `test/incus/test-host-inbound.sh` | Host-inbound services (ssh/ping) reachable per zone config, incl. after failover |
| `test-wire-appmatch-twins` | `test/incus/wire-appmatch-twins.sh` | Application matching distinguishes twin flows |
| `test-wire-routing-separation` | `test/incus/wire-routing-separation.sh` | Routing domains/VRFs do not leak into each other |
| `test-wire-nat-frag-needed` | `test/incus/wire-nat-frag-needed.sh` | NAT + fragmentation-needed handling on the wire |
| `test-wire-conntrack-lifecycle` | `test/incus/wire-conntrack-lifecycle.sh` | Session create/hit/expire lifecycle |
| `test-wire-gate-hermetic-lib` | `test/incus/wire-gate-*.sh` | Hermetic (cluster-free) leg of the wire gates |

Supporting probes: `test/incus/wire_probe_burst.py`,
`wire_raw_tcp_burst.py`, `wire_routing_probe.py`, `wire_tcp_accept.py`,
`wire_tcp_hold.py` (repo burst generator used by the plan's V4
small-packet cell).

## 3. HA, failover, crash & upgrade

| Gate target | Script | Proves |
| --- | --- | --- |
| `test-failover` | `test/incus/test-failover.sh` | Active TCP flows (iperf3 `-P8 --json-stream`) survive fw reboot + manual failback; sessions sync primary→secondary |
| `test-double-failover` | `test/incus/test-double-failover.sh` | Two consecutive RG moves under load |
| `test-stress-failover` | `test/incus/test-stress-failover.sh` | Rapid repeated failover cycles kill no stream (regression gate for dual-inactive/RST bugs) |
| `test-ha-crash` | `test/incus/test-ha-crash.sh` | Hard VM crash / hung daemon recovery (beyond clean-reboot failover) |
| `test-chained-crash` | `test/incus/test-chained-crash.sh` | Crash during recovery from a previous crash |
| `test-active-active` | `test/incus/test-active-active.sh` | Split-RG active/active forwarding both nodes |
| `test-private-rg` | `test/incus/test-private-rg.sh` | Private redundancy-group behaviour |
| `test-rolling-upgrade` | `test/incus/test-rolling-upgrade.sh` | Traffic-carrying two-cut version upgrade with version assertions |
| `test-dhcp-lease-failover` | `test/incus/dhcp-lease-failover.sh` | DHCP leases survive RG failover |
| `test-persistent-nat-failover` | (Makefile target) | Persistent NAT bindings survive failover |
| `test-v6-na-recovery-12495` (script only — no make target; hermetic leg is `make test-v6-na-recovery-lib`) | `test/incus/test-v6-na-recovery-12495.sh` | IPv6 neighbor recovery after RG failover: unsolicited-NA burst vs RA attribution (plan gate V6's harness) |

Drivers that chain the above:

| Harness | Invocation | What it does |
| --- | --- | --- |
| HA validation | `BPFRX_CLUSTER_ENV=<env> ./scripts/userspace-ha-validation.sh` | The plan's V3 driver: 3×5 s iperf3, `PARALLEL=6`, gates `MIN_GBPS_V4/V6=18.0` (run-2+ on new clusters; run-1 records baseline), tail-ratio ≥ 0.35, no zero intervals — parsed by `scripts/iperf-json-metrics.py` |
| Phase cycle | `./scripts/userspace-phase-cycle.sh [--perf] [--fast]` | Push branch → deploy fw0/fw1 → validate (smoke matrix or fast mode); the ship-it loop |
| Metrics oracle | `scripts/iperf-json-metrics.py` | Judges iperf3 JSON: zero-throughput intervals, peak/tail ratio — the failover failure signal is zero intervals, not retransmits. A json-stream `error` event means the client was interrupted (SIGTERMed after hanging past `-t`, typically on a blackholed stream). Such a run is `completed=false` with `client_error` set; `avg_gbps` is the measured-interval mean, not the stub's zero `sum_received`; the closing interval past `-t` is excluded. `iperf_client_interrupt_verdict` (`test/incus/iperf-throughput-lib.sh`) turns it into its own FAIL cell in `test-failover.sh` and `ha-smoke-iperf-lib.sh` (#18543) |

**Known open result on the new clusters:** RG1 manual failover under
iperf on `tcp:` blackholed existing flows ~30 s while new flows worked
(plan note 2026-10-21d-d). `test-failover`/`test-stress-failover`
against `tcp:`/`udp:` is the harness that turns that observation into
a verdict; it has not yet been run there.

## 4. Throughput, latency, CoS & fairness

| Harness | Invocation | What it does |
| --- | --- | --- |
| Perf compare | `BPFRX_CLUSTER_ENV=<env> ./scripts/userspace-perf-compare.sh` | Before/after iperf3 (8 s, `-P4`) with `perf` capture window; regression comparison between builds |
| HA validation (throughput leg) | `scripts/userspace-ha-validation.sh` | See §3 — doubles as the v4/v6 throughput gate |
| Mouse latency | `test/incus/test-mouse-latency.sh <N> <M> <dur> <out>`; `-matrix`, `-same-class` script variants (invoked directly — no `make test-mouse-latency-*` targets) | N elephant streams (1 Gbit/s exact, port 5202) vs M mouse probes (6200); mouse latency distribution under elephant load |
| Fairness harness | `test/incus/fairness-harness.sh` | iperf3 `-P N -J` + per-second `/metrics` scrape; per-binding active-flow fairness gates (`docs/fairness-regimes.md`) |
| Fairness sweeps | `test/incus/fairness-cos-class-sweep.sh`, `fairness-cos-throughput-headroom.sh` | Per-class fairness and headroom cells |
| CoS contention | `test/incus/cos-be-contention-harness.sh`, `cos-simul-load-smoke.sh`, `cos-gate1-small-four-alone.sh` | Best-effort class contention and simultaneous-load CoS behaviour against the target-services grid |
| Perf diagnosis steps | `test/incus/step1-baseline-and-matrix.sh`, `step1-rss-multinomial.py`, `step2-sched-switch-*.py`, `step3-tx-kick-classify.py` | Staged bottleneck attribution: baseline matrix → RSS flow distribution → scheduler switches → TX-kick classification |
| Stall capture | `test/incus/capture-cold-stall.sh`, `scripts/cut_stall_sampler.sh`, `scripts/cut_stall_analyze.py`, `analyze-userspace-traces.sh` | Cold-path/stall sampling and trace analysis on the live helper |

Manual-but-repeatable (used in the 2026-10-21 perf work, not yet a
script): in-guest `perf record -o <file>` on the forwarding node +
data-plane counter deltas; findings in
[xpf-dataplane-perf-diagnosis.md](xpf-dataplane-perf-diagnosis.md). Ad-hoc one-off iperf3 servers
(`iperf3 -s --one-off -p <port>`) remain the fallback until the
target-services grid exists on `tcp`/`udp`.

## 5. Tunnels & interop

| Harness | Invocation | What it does |
| --- | --- | --- |
| Native GRE validation | `BPFRX_CLUSTER_ENV=<env> ./scripts/userspace-native-gre-validation.sh` (`--deploy/--failover/--iperf/--udp/--traceroute`) | GRE transit stays on WAN path, `gr-0-0-0` out of transit, long-lived traffic + failover (plan skill: userspace-native-gre-iperf) |
| WireGuard interop | `test/incus/wg-interop.sh` (`wg-interop.env`) | xpf WireGuard vs independent Linux-kernel WG peer on `loss:xpf-wg-peer` (SR-IOV VF, VLAN 3667): handshake, traffic, rekey |

## 6. Crafted-frame & security probes

| Harness | Invocation | What it does |
| --- | --- | --- |
| Screen probe | `test/incus/screen-probe.sh` (`make test-screen-probe-lib` for the hermetic leg) | Reusable crafted-frame probe for screen (IDS) findings on the shared cluster — exists because a live bypass was twice "unreproducible" with ad-hoc tooling |
| Security matrix (skill) | `.claude/skills/security-matrix` | Agent-runbook: forwarding matrix on real traffic (plain forwarding, trust→untrust ALLOW, untrust→trust BLOCK, trust→trust ALLOW) with captured proof |
| FBF steering | `test/incus/test-fbf-steering.sh` | Flow-based forwarding steering correctness |

## 7. Agent skill runbooks (`.claude/skills/`, `.codex/skills/`)

Skills are operator runbooks an agent executes end-to-end; each wraps
the harnesses above with environment-specific procedure.

| Skill | Wraps | Use for |
| --- | --- | --- |
| `userspace-ha-validation` | `scripts/userspace-ha-validation.sh` on the isolated userspace cluster | Fallback-state checks, IPv6 RA, repeated v4/v6 iperf, optional `perf` on the active FW (§3/V3 numbers and their caveats) |
| `perf-test` | iperf3 + `perf record` on cluster or standalone VM | IPv4/IPv6 throughput + CPU profiling runs |
| `failover-test` | iperf3 through the HA cluster while cycling RG failovers | Throughput floors across failovers, configurable iterations (§3 gates under traffic) |
| `security-matrix` | Wire suite + tcpdump proof | §6 negative gate + zone matrix with captures |
| `userspace-native-gre-iperf` | `scripts/userspace-native-gre-validation.sh` | §5 GRE cells |
| `iperf-grpc-tcpdump` | Synchronised iperf3 + server-side tcpdump over the gRPC capture service | Throughput-collapse / RST / tuple-corruption debugging |

## 8. Plan §6 gates → harness map (per new cluster)

From [incus-tcp-udp-plan.md](incus-tcp-udp-plan.md) §6; `ENV=test/incus/<stack>-userspace-cluster.env`.

| Gate | Harness / command | State on tcp/udp |
| --- | --- | --- |
| V0 idle/collision + VF audit + fabric smoke | Host `tcpdump -i mlx0 vlan 50/80`; `cli show chassis cluster status`; §5-S3 VF audit; fabric `/30` ping + session-sync counters | Partially done by hand in attempt 1 (no formal run; fabric is bridge fallback, so the E810 fabric smoke does not apply) |
| V1 L2/L3 smoke | Manual ping/mtr set from generator (or `make test-connectivity`) | Done by hand, passed post-recovery |
| V2 cross-protocol smoke | One `iperf3 -u` pass (tcp cluster) / one TCP pass (udp cluster) | Done ad-hoc, passed |
| V3 TCP deep | `scripts/userspace-ha-validation.sh` with `V4/V6_TEST_TARGET` overrides + `-R` cells | Not run formally; ad-hoc -P32 baselines recorded (~36–41 Gbit/s) |
| V4 UDP deep | `iperf3 -u -b {1,5,10,20}G -l 1400 -P {1,4}` sweep + burst gen | Partial: 10G/40G single-flow probes only |
| V5 HA failover mid-flow | Long iperf + `request chassis cluster failover redundancy-group 1` (harness form: `test-failover`) | **Failed informally on tcp (existing-flow blackhole ~30 s); formal harness run outstanding** |
| V6 NA/ND & RA | `test/incus/test-v6-na-recovery-12495.sh` (direct script; `make test-v6-na-recovery-lib` for the hermetic leg); manual `ndisc6`/RA-expiry checks | Not run |
| V7 counters snapshot | `cli show chassis cluster data-plane statistics` + PF `ethtool -S` before/after each gate | Done ad-hoc during perf work |

## 9. Harness infrastructure & selftests

| Piece | What it does |
| --- | --- |
| `test/incus/harness-result.sh` | One JSON verdict envelope per gate run → `test/results/ledger.d/`; `make harness-compare` / `harness-coverage` / `harness-ledger-lint` audit it |
| `test/incus/with-cluster.sh` + `cluster-cell.sh` + `cluster-lock.sh` | The #1875 exclusive lock cell every destructive harness runs inside; standalone runs queue |
| `test/incus/active-fw.sh` | Resolves which node currently forwards (RG owner) for a cluster env |
| `*-selftest.sh` / `*-lib` make targets (60+) | Hermetic, cluster-free tests of each harness's own library — run before trusting a harness edit (`make test-<name>-lib`) |
| `scripts/harness-census.sh` (`make harness-census`) | Census of harnesses vs ledger coverage — finds harnesses with no recorded runs |
| `make selftest` / `scripts/run-selftests.sh` | Repo-wide selftest sweep |

## 10. Non-cluster test entry points (for completeness)

| Target | Covers |
| --- | --- |
| `make test` / `test-go` / `test-race-dp` | Go unit + race suites (incl. dataplane-adjacent packages) |
| `make test-rust` | `userspace-dp` cargo suite (the 60k-line `*_tests.rs` estate beside the sources) |
| `make test-root` | `test-shim-run`, memlock guards, xfrm lifecycle (root-required legs) |
| `make test-miri` | Miri UB checks for the Rust dataplane |

These do not touch the clusters; listed because dataplane fixes from
the perf diagnosis are gated by `test-rust`/`test-miri` before any
live re-run under §4.
