# xpf - eBPF Firewall with Junos Configuration Syntax

> Deprecation notice (#1373): the legacy eBPF dataplane is being retired in
> favor of the Rust AF_XDP userspace dataplane. New dataplane development should
> target `userspace-dp`. Phase 0 is documentation/audit only and removes no BPF
> source.

## Working Style
- Think before acting. Read existing files before writing code.
- Be concise in output but thorough in reasoning.
- Prefer editing over rewriting whole files.
- Do not re-read files you have already read.
- Test your code before declaring done.
- When modifying code or changing behavior, update the relevant module
  documentation in the corresponding Markdown files as part of the same work.
  Treat README/design/state/operator docs as part of the module contract; if no
  docs change is needed, say why in the review notes.
- No sycophantic openers or closing fluff.
- Keep solutions simple and direct.
- When working with many teams, don't let the context windows get too large.

**Read `docs/engineering-style.md` before writing non-trivial code or
reviewing a PR.** It encodes the coding and review discipline this
project has settled on — hot-path allocation rules, review severity,
compile-time invariants, PR discipline, and the project-specific
gotchas that repeatedly bite (deploy wipes CoS, iperf3 target, etc.).

## Logging Rules
- Maintain a log of all major actions in `_Log.md`.
- Use YAML or Markdown bullet points for structure:
    - **Timestamp**: [Time]
    - **Action**: [Brief Description]
    - **File(s)**: [Modified Files]
- Log every `[Write|Edit]` action.
- **Go**: Use `slog.Debug` for high-frequency/diagnostic messages (HA watchdog sync, per-session traces). Use `slog.Info` only for state transitions and one-time events. HA watchdog sync was flooding at 15 req/s with `slog.Info` — caused 35K+ log lines per session and drowned real diagnostics.
- **Rust helper**: `eprintln!("xpf-ha: ...")` goes to journald via stderr. Use sparingly — remove debug eprints before committing. Keep per-worker `RefreshOwnerRGs`/`FlushFlowCaches` logs (they fire rarely, only on RG transitions).
- **Never** add `slog.Info` inside loops that run per-packet, per-session, or per-poll-tick. If you need per-tick logging, use `slog.Debug`.
- **Control socket contention**: The userspace helper control socket is shared by status poll (1/s), HA sync, session installs, snapshot sync, and forwarding sync. High-frequency callers MUST be throttled. Adding a new control socket request at >1/s will starve session installs during bulk sync.

## What This Is
An eBPF-based firewall that clones Juniper vSRX capabilities using native Junos configuration syntax. Go userspace (cilium/ebpf) drives C eBPF programs attached at XDP (ingress) and TC (egress).

## Quick Start
```bash
make generate        # Generate Go bindings from BPF C via bpf2go
make build           # Build xpfd daemon
make build-ctl       # Build remote CLI client
make test            # Run Go tests (640+ tests across 20 packages)
```

## Test Environment (Incus VM)
```bash
make test-env-init   # One-time: install incus, create networks + profiles
make test-vm         # Create Debian 13 VM with FRR, strongSwan
make test-deploy     # Build -> push binary + config + unit -> systemctl enable --now
make test-ssh        # Shell into VM
make test-status     # Instance + service + network info
make test-logs       # journalctl -u xpfd -n 50
make test-journal    # journalctl -u xpfd -f (follow)
make test-start      # systemctl start xpfd
make test-stop       # systemctl stop xpfd
make test-restart    # systemctl restart xpfd
make test-destroy    # Tear down VM
```

If `incus` commands fail with permission errors, use `sg incus-admin -c "make ..."`.

## Cluster Test Environment (Two-VM HA)

**Smoke tests run ONLY on the loss userspace cluster** (`loss:xpf-userspace-fw0/fw1`).
The local `make cluster-*` targets drive the legacy eBPF cluster
(`bpfrx-fw0/1`) which is regression-only; never use them for smoke.

```bash
# === SMOKE (loss userspace cluster, default for all userspace-dp validation) ===
export BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
./test/incus/cluster-setup.sh deploy all
./test/incus/cluster-setup.sh ssh 0
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0   # deploy wipes CoS — re-apply

# === LEGACY (local bpfrx-fw0/1, regression-only — do NOT use for smoke) ===
make cluster-init              # Create networks + profile for legacy HA cluster
make cluster-create            # Launch bpfrx-fw0, bpfrx-fw1, cluster-lan-host
make cluster-deploy            # Build + push to both legacy VMs + restart
make cluster-destroy           # Tear down legacy cluster VMs
make test-failover             # Reboot fw0 during iperf3 — verify TCP survives failover+failback
make test-ha-crash             # Force-stop/daemon-stop/multi-cycle crash recovery
make test-restart-connectivity # Verify 0 packet loss during daemon restart
```

Or use `test/incus/cluster-setup.sh` directly with `BPFRX_CLUSTER_ENV` set:
`{init|create|deploy all|destroy|ssh 0|1|status|logs 0|1}`.

**IMPORTANT:** Any change touching cluster, VRRP, session sync, or failover code MUST pass `make test-failover` before commit.

## Architecture

The BPF pipeline below is legacy context during the #1373 retirement. Keep it
working until the staged removal phases land, but do not start new dataplane
features on this path unless a blocker explicitly requires compatibility work.

### BPF Pipeline (14 programs, tail calls)
```
XDP Ingress: main -> screen -> zone -> conntrack -> policy -> nat -> nat64 -> forward
TC Egress:   main -> screen_egress -> conntrack -> nat -> forward
```

### Key Design Patterns
- **Per-CPU scratch map** passes metadata between tail-call stages
- **Dual session entries** (forward + reverse) in conntrack HASH map
- **NAT "meta as desired state"**: pipeline stages set meta fields, xdp_nat reconciles packet
- **Three-phase config compilation**: Junos AST -> typed Go structs -> eBPF map entries
- **FRR-managed routing**: all routes (static, DHCP, per-VRF) via managed section in `/etc/frr/frr.conf`
- **Full interface management**: xpfd owns ALL interfaces on the firewall — renames them via `.link` files, configures addresses/DHCP via `.network` files, and brings down unconfigured interfaces

### APIs
- **gRPC** on 127.0.0.1:50051 — 48+ RPCs (config, sessions, stats, routes, IPsec, DHCP, cluster)
- **HTTP REST** on 127.0.0.1:8080 — health, Prometheus metrics, config endpoints
- **CLI** — Interactive Junos-style with tab completion, `?` help, `| match` pipe
- **Remote CLI** — `cli` binary connects via gRPC
- **Command Trees** — `pkg/cmdtree/tree.go` is single source of truth for all CLI command trees, tab completion, and `?` help across local CLI, remote CLI, and gRPC server

## Code Layout
| Path | Description |
|------|-------------|
| `bpf/headers/*.h` | Shared C structs (common, maps, helpers, conntrack, nat) |
| `bpf/xdp/*.c` | 9 XDP ingress programs (includes cpumap entry) |
| `bpf/tc/*.c` | 5 TC egress programs |
| `pkg/config/` | Junos parser, AST, typed config, compiler |
| `pkg/cmdtree/` | Single source of truth for all CLI command trees |
| `pkg/configstore/` | Candidate/active/commit/rollback, atomic DB persistence, JSONL audit journal |
| `pkg/dataplane/` | eBPF loader, map management, bpf2go bindings |
| `pkg/daemon/` | Daemon lifecycle (TTY detection, signal handling) |
| `pkg/cluster/` | Chassis cluster HA (state machine, session sync, config sync, IPsec SA sync) |
| `pkg/cli/` | Interactive Junos-style CLI |
| `pkg/conntrack/` | Session garbage collection (with HA delete sync callbacks) |
| `pkg/logging/` | Ring buffer reader, event buffer, syslog client |
| `pkg/dhcp/` | DHCPv4/DHCPv6 clients |
| `pkg/frr/` | FRR config generation + managed section in frr.conf |
| `pkg/networkd/` | systemd-networkd .link/.network file generation |
| `pkg/routing/` | GRE tunnels, VRFs, XFRM interfaces, rib-group + next-table route leaking via netlink |
| `pkg/ipsec/` | strongSwan config + SA queries |
| `pkg/api/` | HTTP REST API + Prometheus collector |
| `pkg/grpcapi/` | gRPC server + protobuf bindings |
| `pkg/flowexport/` | NetFlow v9 exporter |
| `pkg/feeds/` | Dynamic address feed fetcher |
| `pkg/dhcpserver/` | Kea DHCP server management |
| `pkg/eventengine/` | Event-driven automation engine |
| `pkg/rpm/` | RPM probe manager |
| `proto/xpf/v1/` | Protobuf service definition |
| `cmd/xpfd/` | Daemon main binary |
| `cmd/cli/` | Remote CLI client binary |
| `dpdk_worker/` | DPDK C pipeline (single-pass packet processing, CGo bridge) |
| `pkg/dataplane/dpdk/` | DPDK Go manager (CGo shared memory, FIB sync, port stats) |
| `pkg/vrrp/` | Native VRRPv3 state machine (30ms RETH advertisements, AF_PACKET, IPv6 NODAD) |
| `pkg/ra/` | Embedded RA sender (replaces radvd) |
| `docs/` | Protocol docs, feature gaps, phase notes, test plans, memory backups |
| `test/incus/` | Test environment (setup.sh, config, systemd unit) |

## Critical Patterns to Know

### Byte Order
- Use `binary.NativeEndian.Uint32(ip4)` for BPF `__be32` fields — **NOT** `BigEndian`
- cilium/ebpf serializes map values in native endian; IP bytes are already in network order

### C/Go Struct Alignment
- When mirroring C structs in Go for cilium/ebpf, always match `sizeof` in C
- Add trailing `Pad [N]byte` fields to reach C compiler's struct alignment

### Parser Dual AST Shape & Set Syntax Testing
- Hierarchical `family inet { dhcp; }` → `Node{Keys:["family","inet"]}` with children
- Flat `set interfaces eth0 unit 0 family inet dhcp` → `Node{Keys:["family"]}` with child `Node{Keys:["inet"]}`
- Compiler must handle **both** shapes
- **Testing flat set syntax:** ALWAYS use `ParseSetCommand()` + `tree.SetPath()` loop, NEVER `NewParser()` — the parser treats newlines as whitespace and will merge all set lines into one giant node

### BPF Verifier
- Branch merges lose packet range — re-read `ctx->data`/`ctx->data_end` after branches
- Combined stack limit is 512 bytes across call frames — use `__noinline` and scratch maps
- Variable-offset pkt pointer: verifier refuses range tracking when `var_off` is wide (0xffff) — use constant-offset from validated pointer instead
- **Narrowing meta offsets**: when using `meta->l3_offset` (u16) for packet pointer math, mask with `& 0x3F` to narrow var_off so verifier can track range (`66833c5`)
- `__u16` type causes sign-extension (`smin=-32768`) — fails for pkt pointer math
- `iter.Next(&key, nil)` crashes in cilium/ebpf v0.20 — always use `var val []byte`
- xdp_zone fails verifier on kernel 6.12 (NAT64 complexity) — passes on 6.18+

### TTY Detection
- Use `unix.IoctlGetTermios(fd, TCGETS)` — **not** `os.ModeCharDevice` (`/dev/null` is a CharDevice)

### Interface Management (networkd)
- **xpfd manages ALL interfaces** on the firewall — no external networkd configs needed
- Every interface must be defined in the firewall config and assigned to a security zone
- Interfaces not in the config are brought down and marked `ActivationPolicy=always-down` in networkd
- VRF devices and tunnel interfaces created by the daemon are excluded from unmanaged detection
- **`.link` files**: written per-interface, prefix `10-xpf-`, rename kernel names (enp7s0→ge-0-0-0)
  - Startup naming: `enumerateAndRenameInterfaces()` in `pkg/daemon/linksetup.go` runs at daemon start, assigns vSRX names (fxp0, em0, ge-{FPC}-0-{PORT})
  - Non-RETH interfaces: match by `MACAddress=` (MAC is stable)
  - RETH member interfaces: match by `OriginalName=` (PCI kernel name) — MAC alternates between physical (boot) and virtual (daemon), so `MACAddress=` is unreliable
  - `ensureRethLinkOriginalName()` auto-fixes stale `.link` files that use `MACAddress=` for RETH members
- **`.network` files**: configure addresses (static), DHCP avoidance, RA disable, VLAN parent flags
  - `KeepConfiguration=static` on RETH interfaces preserves VRRP VIPs across `networkctl reload`
- Stale files are auto-removed; `networkctl reload` called only when files actually change
- **DHCP interfaces**: daemon's DHCP client manages the address; address reconciliation is skipped
- **Bootstrap**: daemon's `enumerateAndRenameInterfaces()` runs at startup, writes `.link` files + bootstrap fxp0 DHCP `.network`
- DHCP-learned default routes get admin distance 200 in FRR (lower priority than static routes)

### XDP on SR-IOV Interfaces
- **iavf (VF driver) has NO native XDP support** — only generic/SKB mode works, which creates a full `sk_buff` per packet (~16% CPU overhead from `memcpy_orig` + `memset_orig`). Performance drops from 25+ Gbps to ~6.8 Gbps
- **i40e/ice (PF driver) has native XDP** — driver-mode XDP processes packets before SKB allocation, much faster
- **`bpf_redirect_map` requires `ndo_xdp_xmit` on target** — you cannot redirect from a native XDP program to an interface that lacks native XDP support. If the target doesn't implement `ndo_xdp_xmit`, the redirect silently fails. This means mixing native+generic interfaces in a redirect set does not work
- **xpf workaround: `redirect_capable` map** — per-interface flag checked in `xdp_forward.c`. Interfaces without native XDP get `XDP_PASS` (kernel forwarding path) instead of `bpf_redirect_map`. This lets native interfaces redirect between each other while non-native interfaces fall back to kernel forwarding
- **XDP on PF does NOT see VF traffic** — SR-IOV hardware switching delivers VF packets directly to VFs, bypassing the PF's XDP program entirely. You cannot use PF XDP to firewall VF traffic. Each VF would need its own XDP program (but iavf doesn't support native XDP, so that's generic-only)
- **Current test env uses PF passthrough (i40e)** — the entire PF (`enp10s0f0np0`) is passed through to the VM via VFIO, not a VF. This gives native XDP on the WAN interface. All interfaces (virtio + i40e PF) run native XDP
- **Why not VF passthrough** — VFs use the iavf driver which forces generic mode. Even with the `redirect_capable` workaround, the WAN interface itself runs in generic XDP which is slower for ingress processing. PF passthrough avoids this entirely
- **Gotcha: PF passthrough claims the whole NIC** — no VFs can be used by other VMs when the PF is passed through. For multi-VM setups, VF passthrough with generic XDP + `redirect_capable` fallback is the only option (at a performance cost)

### Chassis Cluster (HA)
- **Failover timing**: ~60ms with 30ms VRRP intervals (masterDownInterval ~97ms); configurable via `set chassis cluster reth-advertise-interval <ms>`
- **Planned shutdown**: burst of 3× priority-0 adverts; peer takes over in ~1ms (immediate takeover on priority-0)
- **Failback timing**: ~130ms (daemon startup + BPF load + sync hold release)
- **VRRP advertisement**: RETH instances default 30ms; `AdvertiseInterval` is milliseconds internally, centiseconds on wire per RFC 5798
- **Async GARP**: `becomeMaster()` runs GARP in a goroutine — first pair <1ms, remaining at 50ms intervals in background. Critical path: addVIPs → sendAdvert → emitEvent (sync), then go sendGARP() (async)
- **Fabric forwarding**: `try_fabric_redirect()` in xdp_zone redirects to fabric peer when `bpf_fib_lookup` fails for synced sessions — prevents TCP death on VRRP failback
- **RETH virtual MAC**: per-node `02:bf:72:CC:RR:NN`; `programRethMAC()` does link DOWN→set MAC→link UP
- **VIP reconciliation**: `ReconcileVIPs()` re-adds VRRP VIPs after `programRethMAC` link DOWN/UP (which removes all kernel addresses)
- **Sync hold**: VRRP starts with `preempt=false`; released after bulk session sync (or 10s timeout); `preemptNowCh` triggers instant preemption
- **Heartbeat**: 200ms interval, threshold 5 (1s detection); bind retry loop for simultaneous boot
- **Session sync connect**: immediate first attempt, 1s retry (was 5s)
- **Event debounce**: 500ms for cluster state → VRRP priority updates

### Shutdown
- FRR reload commands use 15s context timeout to prevent hanging on `systemctl reload frr`
- systemd unit has `TimeoutStopSec=20` as safety net, `RestartSec=1`

## Feature Coverage
- **Firewall**: Stateful inspection, zone-based policies (including global policies), address books, application matching, multi-term apps, filtered session clearing
- **NAT**: SNAT (interface + pool, address-persistent), DNAT (with hit counters), static 1:1, NAT64 (native BPF)
- **IPv4 + IPv6**: Dual-stack, DHCPv4/v6 clients, Router Advertisements
- **Screen/IDS**: 11 checks (land, syn-flood, ping-death, teardrop, rate-limiting), SYN cookie flood protection (XDP-generated SYN-ACK cookies with source validation)
- **Routing**: FRR integration (static, OSPF, BGP, IS-IS, RIP), VRFs, GRE tunnels, export/redistribute, ECMP multipath, next-table + rib-group inter-VRF route leaking, route filtering by protocol/CIDR
- **VLANs**: 802.1Q tagging in BPF, trunk ports
- **IPsec**: strongSwan config generation, IKE proposals, gateway compilation, XFRM interfaces
- **Observability**: Syslog (facility/severity/category filtering, structured RT_FLOW format, TCP/TLS transport, event mode local file), NetFlow v9 (1-in-N sampling), Prometheus, RPM probes, dynamic feeds, SNMP (ifTable MIB), BPF map utilization (`show system buffers`), session aggregation reporting
- **Flow**: TCP MSS clamping (ingress XDP + egress TC, including GRE-specific gre-in/gre-out), ALG control, allow-dns-reply (wired to BPF), allow-embedded-icmp, configurable timeouts (per-application inactivity), firewall filters (port ranges, hit counters, logging, forwarding-class DSCP rewrite, DSCP action)
- **HA**: Chassis cluster state machine (weight-based failover, manual failover/reset, Junos-style show/request commands), native VRRPv3 (Go state machine, AF_PACKET receiver, per-instance sockets, IPv6 NODAD, 30ms RETH advertisements, async GARP burst, ~60ms failover), bondless RETH (VRRP on physical member interfaces, RethToPhysical resolution, per-node virtual MAC), incremental session sync (1s sweep + ring buffer + GC delete callbacks), config sync (forward + reverse-sync on reconnect, ${node} variable quoting), IPsec SA sync, fabric cross-chassis forwarding, ISSU
- **DHCP**: Relay (Option 82), server (Kea integration with lease display)
- **CLI**: Junos-style prefix matching, "Possible completions:" headers, zone/interface descriptions, session idle time, session brief tabular view, flow statistics, policy descriptions, config validation warnings

## Network Topology (Test VM)

All interfaces are managed by xpfd — renamed via `.link` files, configured via `.network` files.
Startup naming by `enumerateAndRenameInterfaces()` assigns vSRX names based on PCI bus order.

```
Standalone VM (xpf-fw) — no /etc/xpf/node-id, no em0:
  Virtio (PCI bus 05-08):
    enp5s0  → fxp0       DHCP          — mgmt zone (SSH + ping)
    enp6s0  → ge-0-0-0   10.0.1.10     — trust zone
    enp7s0  → ge-0-0-1   10.0.2.10     — untrust zone
    enp8s0  → ge-0-0-2   10.0.30.10    — dmz zone
  i40e PCI passthrough (PCI bus 09+, always higher than virtio):
    enp9s0f0np0   → ge-0-0-3  172.16.50.5  — wan zone (VLAN 50, IPv6)
    enp101s0f1np1 → ge-0-0-4               — loss zone

Test containers:
  trust-host    10.0.1.102  (2001:559:8585:bf01::102)  — xpf-trust bridge
  untrust-host  10.0.2.102  (2001:559:8585:bf02::102)  — xpf-untrust bridge
  dmz-host      10.0.30.101 (2001:559:8585:bf03::101)  — xpf-dmz bridge
```
