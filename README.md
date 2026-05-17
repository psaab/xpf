# xpf

Stateful firewall with native Junos configuration syntax.

> Deprecation notice (#1373): the Rust AF_XDP userspace dataplane is now the
> primary/default target for dataplane development and validation. The legacy
> eBPF dataplane remains in-tree for compatibility, rollback, and regression
> coverage during the staged retirement. Phase 1 updates active documentation;
> later phases own source, loader, build, and CLI removals.

xpf is a high-performance stateful firewall that replicates Juniper vSRX
capabilities. It uses the familiar Junos hierarchical configuration syntax and
provides a full interactive CLI with tab completion and `?` help.

## Dataplane Architecture

xpf provides dataplane backends selectable via configuration. Both share the
same Go control plane (config, HA, routing, CLI, APIs); only the packet
forwarding path differs.

The userspace AF_XDP backend is the primary retirement target. It is still
selected explicitly with `system dataplane-type userspace`; if that knob is
omitted, the current code falls back to the legacy eBPF backend until a later
cutover phase changes runtime defaults. New dataplane feature work should use
the userspace path and close blockers tracked in
[`docs/userspace-dataplane-gaps.md`](docs/userspace-dataplane-gaps.md).

### Userspace Dataplane (primary target)

A Rust-based forwarding engine receives packets via AF_XDP sockets and
processes them in userspace. A Rust XDP shim stamps metadata, redirects transit
traffic into AF_XDP, and still hands kernel-owned or unsupported traffic back
to the kernel or legacy BPF path when needed.

```
NIC → XDP shim (live-session + new-flow redirect, kernel pass-through, explicit fallback)
    → AF_XDP socket
    → Rust worker thread (session → policy → NAT → FIB → TX)
    → AF_XDP TX ring → NIC
```

- **Per-worker architecture**: one worker per queue shard, with session/NAT/policy/FIB handled in Rust
- **AF_XDP fast path**: current code supports both copy and zero-copy modes depending on driver/path behavior
- **Kernel pass-through**: cpumap-assisted delivery keeps local/kernel-owned traffic out of the AF_XDP fast path
- **Automatic fallback**: unsupported configs and explicit error paths still fall back to the legacy eBPF dataplane
- **Best for**: new dataplane development, primary validation, and high-throughput transit forwarding on supported configs
- **See**: [`docs/userspace-dataplane-architecture.md`](docs/userspace-dataplane-architecture.md) for the current architecture and [`docs/userspace-debug-map.md`](docs/userspace-debug-map.md) for the active debugging map

**To select the userspace dataplane:**

```junos
system {
    dataplane-type userspace;
    dataplane {
        binary /usr/local/sbin/xpf-userspace-dp;
        workers 6;
        ring-entries 8192;
    }
}
```

### Legacy eBPF Dataplane (compatibility/regression)

The original dataplane runs in-kernel using 14 BPF programs chained via tail calls:

```
XDP Ingress: main -> screen -> zone -> conntrack -> policy -> nat -> nat64 -> forward
TC Egress:   main -> screen_egress -> conntrack -> nat -> forward
```

- **Legacy coverage**: compatibility, rollback, and targeted regression tests
- **Historical performance**: 25+ Gbps on native XDP (mlx5, i40e, ice)
- **Best for**: reproducing legacy behavior while #1373 retirement blockers are being closed

### Dataplane Comparison

| Capability | Legacy eBPF | Userspace AF_XDP (primary target) |
|------------|---------------|-----------|
| Stateful forwarding | Yes | Yes |
| Zone + global policies | Yes | Yes |
| Application matching | Yes | Yes |
| Source NAT (interface + pool) | Yes | Interface and pool mode yes; userspace `address-persistent` uses a documented userspace-v1 hash. Per-pool `persistent-nat`, pool exhaustion counters, and cross-backend new-flow parity remain #1377 work |
| Destination NAT | Yes | Yes |
| Static NAT (1:1) | Yes | Yes |
| NAT64 (IPv6↔IPv4) | Yes | Yes |
| NPTv6 (RFC 6296) | Yes | Yes |
| Screen/IDS (11 checks) | Yes | Most checks yes; SYN-cookie behavior falls back |
| Firewall filters + policers | Yes | Filters yes; three-color policers admitted for color-blind `then discard` slice, with remaining #1375 hardening still open |
| TCP MSS clamping | Yes | Yes |
| GRE tunnel transit | Yes | Yes (passthrough) |
| IPsec / XFRM | Yes | Yes (passthrough) |
| VLANs (802.1Q) | Yes | Yes |
| Flow export (NetFlow v9) | Yes | Yes |
| HA cluster + session sync | Yes | Integrated, but still under active hardening |
| SYN cookie flood protection | Yes | No (fallback) |
| Throughput (25G mlx5) | 22+ Gbps | See validation/perf docs for current results |

The userspace dataplane now covers most of the transit feature set in native
Rust, but it is not "fallback-free". Current explicit gates in code still
include SYN-cookie-dependent screen behavior and port mirroring. Three-color
policers are admitted only for the bounded color-blind `then discard` runtime
slice while #1375 hardening remains. Pool-mode SNAT is admitted, and #1385
added userspace-v1 `address-persistent` selection; #1377 still owns per-pool
`persistent-nat` lease reuse, allocator/exhaustion counters, and the
mixed-backend rollback boundary. The exact admission boundary is documented in
[`docs/userspace-dataplane-gaps.md`](docs/userspace-dataplane-gaps.md).

## Architecture

- **Go control plane** handles config compilation, session GC, management APIs, HA cluster, and routing
- **Rust AF_XDP userspace dataplane** owns the primary packet-forwarding target
- **Legacy eBPF dataplane** remains available for compatibility and regression coverage
- **Dual session entries** (forward + reverse) in conntrack hash map
- **Three-phase config compilation**: Junos AST → typed Go structs → dataplane snapshots or legacy map entries

## Features

### Firewall & Security
- **Zone-based policies** with stateful inspection, address books, application matching, global policies
- **NAT**: source (interface + pool, userspace-v1 address-persistent), destination (with hit counters), static 1:1, NAT64, NPTv6 (RFC 6296 stateless prefix translation)
- **Dual-stack**: IPv4 + IPv6, DHCPv4/v6 clients, embedded Router Advertisement sender (replaces radvd), SLAAC
- **Screen/IDS**: 11 checks (land, SYN flood, ping of death, teardrop, SYN-FIN, no-flag, winnuke, FIN-no-ACK, rate-limiting), SYN cookie flood protection (XDP-generated SYN-ACK cookies)
- **Firewall filters**: policer (token bucket + three-color), lo0 filter, flexible match, port ranges, hit counters, logging, forwarding-class DSCP rewrite

### Flow Processing
- **TCP MSS clamping** (ingress XDP + egress TC, including GRE-specific gre-in/gre-out)
- **ALG control**, allow-dns-reply, allow-embedded-icmp
- **Configurable timeouts** (per-application inactivity)
- **Session management**: filtered clearing, idle time tracking, brief tabular view, aggregation reporting

### Routing & Networking
- **FRR integration**: static, OSPF, BGP, IS-IS, RIP, ECMP multipath, export/redistribute
- **VRFs** with inter-VRF route leaking (next-table + rib-group)
- **GRE tunnels**, XFRM interfaces, PBR (policy-based routing)
- **VLANs**: 802.1Q tagging, trunk ports
- **IPsec**: strongSwan config generation, IKE proposals, gateway compilation
- **Full interface management**: xpfd owns ALL interfaces — renames via `.link` files, configures addresses/DHCP via `.network` files, brings down unconfigured interfaces

### High Availability
- **Chassis cluster** with ~60ms failover (30ms VRRP intervals)
- **Native VRRPv3**: Go state machine, AF_PACKET, per-instance sockets, IPv6 NODAD, 30ms RETH advertisements, async GARP burst
- **Bondless RETH**: VRRP on physical member interfaces, per-node virtual MAC (`02:bf:72:CC:RR:NN`), no Linux bonding required
- **Session sync**: incremental 1s sweep + ring buffer + GC delete callbacks, TCP on fabric link
- **Config sync**: primary → secondary with `${node}` variable expansion, reverse-sync on reconnect
- **IPsec SA sync**: shared IKE/ESP state across cluster nodes
- **Dual fabric links**: independent fab0/fab1 for redundancy (no bonding)
- **Fabric cross-chassis forwarding**: `try_fabric_redirect()` redirects to peer when FIB fails for synced sessions
- **Dataplane watchdogs**: legacy BPF pins and userspace heartbeat checks fail closed on daemon/helper failure
- **Readiness gate**: per-RG readiness (interfaces + VRRP) + hold timer gates election
- **Planned shutdown**: near-instant takeover (priority-0 burst), failback ~130ms
- **ISSU**: in-service software upgrade with rolling deploy
- **RA lifecycle**: goodbye RAs (lifetime=0) on failover/startup to prevent stale IPv6 ECMP routes

### Observability
- **Syslog**: facility/severity/category filtering, structured RT_FLOW format, TCP/TLS transport, event mode local file
- **NetFlow v9**: 1-in-N sampling
- **Prometheus metrics** (`/metrics` endpoint)
- **SNMP**: system + ifTable MIB
- **RPM probes**, dynamic address feeds
- **Dataplane buffer utilization** (`show system buffers`): BPF map occupancy on eBPF, AF_XDP UMEM/TX-ring capacity on userspace
- **LLDP**: link layer discovery protocol

### Management
- **Interactive CLI**: Junos-style prefix matching, tab completion, `?` help, pipe filters (`| match`, `| count`, `| except`)
- **Remote CLI**: `cli` binary connects via gRPC with full tab/`?` parity
- **gRPC API**: 48+ RPCs (config, sessions, stats, routes, IPsec, DHCP, cluster)
- **REST API**: HTTP on port 8080 (health, Prometheus, config, full gRPC parity)
- **Config management**: candidate/active with commit model, 50 rollback slots, `load override`/`load merge`, `show | display set`
- **Configure mode protection**: blocked on secondary cluster nodes (RG0 primary is config authority)
- **DHCP server**: Kea integration with lease display
- **DHCP relay**: Option 82 support
- **Event engine**: event-driven automation

## Quick Start

```bash
make generate           # Generate Go bindings from BPF C (requires clang + bpf headers)
make build              # Build xpfd daemon (embeds version from git)
make build-ctl          # Build remote CLI client
make build-userspace-dp # Build Rust AF_XDP dataplane binary (requires cargo)
make test               # Run 1020+ tests across 24 packages
```

## Configuration

xpf uses Junos-style configuration syntax:

```junos
interfaces {
    trust0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                trust0;
            }
            host-inbound-traffic {
                system-services {
                    ssh;
                    ping;
                }
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
```

The config supports both hierarchical `{ }` blocks and flat `set` commands:

```
set interfaces trust0 unit 0 family inet address 10.0.1.1/24
set security zones security-zone trust interfaces trust0
set security policies from-zone trust to-zone untrust policy allow-all match source-address any destination-address any application any
set security policies from-zone trust to-zone untrust policy allow-all then permit
```

## Management Interfaces

- **Local CLI**: run `xpfd` in a TTY for interactive Junos-style shell
- **Remote CLI**: `cli -addr <host>:50051` connects via gRPC
- **gRPC API**: 48+ RPCs on port 50051 (config, sessions, stats, routes, IPsec, DHCP, cluster)
- **REST API**: HTTP on port 8080 (health, Prometheus `/metrics`, config endpoints)

## Performance

- **eBPF dataplane**
  - Legacy compatibility/regression backend during #1373 retirement
  - **25+ Gbps** with native XDP (i40e/ice PF passthrough)
  - **15.6 Gbps** with virtio-net
  - **Hitless restarts** with zero packet loss
  - **~60ms cluster failover** (30ms VRRP, ~97ms masterDown interval)
  - **Near-instant planned shutdown** (priority-0 burst, peer takes over in ~1ms)
- **Userspace dataplane**
  - **AF_XDP-based forwarding** with per-worker Rust session/NAT/policy/FIB processing
  - **Copy or zero-copy mode** depending on NIC driver/path behavior
  - **Kernel pass-through via cpumap** for local and other kernel-owned traffic
  - **See** [`docs/userspace-ha-validation.md`](docs/userspace-ha-validation.md) and [`docs/userspace-perf-compare.md`](docs/userspace-perf-compare.md) for current validation and profiling workflow

## Test Environment

An Incus-based test environment provisions Debian VMs with FRR, strongSwan, and test containers:

```bash
# Single VM (standalone firewall)
make test-env-init   # One-time setup
make test-vm         # Create VM
make test-deploy     # Build + deploy + restart service
make test-logs       # View daemon logs

# Two-VM HA cluster (defaults to loss userspace cluster)
make cluster-init    # Create networks + profile
make cluster-create  # Launch xpf-userspace-fw0 + xpf-userspace-fw1 + LAN host
make cluster-deploy  # Rolling deploy: secondary first, then primary (preserves traffic)
```

Userspace dataplane testing (requires mlx5 NICs on loss cluster):

```bash
# Userspace HA cluster
make cluster-deploy
./scripts/userspace-ha-validation.sh --env test/incus/loss-userspace-cluster.env
./scripts/userspace-perf-compare.sh
```

### Cluster Deployment

`make cluster-deploy` performs a **rolling deploy** to maintain traffic continuity:

1. Determines which node is currently secondary
2. Deploys to the secondary (primary continues forwarding traffic)
3. Waits for the secondary to sync sessions from the primary
4. Deploys to the primary (upgraded secondary takes over via VRRP failover)

To deploy to a single node: `make cluster-deploy NODE=0` or `make cluster-deploy NODE=1`.

### Test Suite

| Test | Command | Description |
|------|---------|-------------|
| Unit tests | `make test` | 1020+ Go tests across 24 packages |
| Connectivity | `make test-connectivity` | End-to-end IPv4/IPv6 routing and SNAT |
| Failover | `make test-failover` | iperf3 survives fw0 reboot (session sync + VRRP) |
| Hard crash | `make test-ha-crash` | Force-stop, daemon stop, multi-cycle crash recovery |
| Restart | `make test-restart-connectivity` | Zero packet loss during daemon restart |
| Private RG | `./test/incus/test-private-rg.sh` | VRRP elimination via private-rg-election |

## Code Layout

| Path | Description |
|------|-------------|
| `bpf/headers/*.h` | Shared C structs (common, maps, helpers, conntrack, nat) |
| `bpf/xdp/*.c` | Legacy XDP ingress programs (includes cpumap entry) |
| `bpf/tc/*.c` | Legacy TC egress programs |
| `pkg/config/` | Junos parser, AST, typed config, compiler |
| `pkg/cmdtree/` | Single source of truth for all CLI command trees |
| `pkg/configstore/` | Candidate/active/commit/rollback, atomic DB persistence |
| `pkg/dataplane/` | Legacy eBPF loader, map management, bpf2go bindings, shared dataplane interface |
| `pkg/dataplane/userspace/` | Go manager for the Rust userspace dataplane |
| `pkg/daemon/` | Daemon lifecycle, reconciliation, interface management |
| `pkg/cluster/` | Chassis cluster HA (state machine, session sync, config sync) |
| `pkg/vrrp/` | Native VRRPv3 state machine (30ms RETH advertisements) |
| `pkg/ra/` | Embedded RA sender (replaces radvd) |
| `pkg/cli/` | Interactive Junos-style CLI |
| `pkg/conntrack/` | Session garbage collection (with HA delete sync) |
| `pkg/logging/` | Ring buffer reader, event buffer, syslog client |
| `pkg/dhcp/` | DHCPv4/DHCPv6 clients |
| `pkg/frr/` | FRR config generation + managed section in frr.conf |
| `pkg/networkd/` | systemd-networkd .link/.network file generation |
| `pkg/routing/` | GRE tunnels, VRFs, XFRM interfaces, route leaking |
| `pkg/ipsec/` | strongSwan config + SA queries |
| `pkg/api/` | HTTP REST API + Prometheus collector |
| `pkg/grpcapi/` | gRPC server + protobuf bindings |
| `pkg/flowexport/` | NetFlow v9 exporter |
| `pkg/feeds/` | Dynamic address feed fetcher |
| `pkg/dhcpserver/` | Kea DHCP server management |
| `pkg/dhcprelay/` | DHCP relay with Option 82 |
| `pkg/eventengine/` | Event-driven automation engine |
| `pkg/rpm/` | RPM probe manager |
| `pkg/snmp/` | SNMP agent (system + ifTable MIB) |
| `pkg/lldp/` | LLDP protocol |
| `proto/xpf/v1/` | Protobuf service definition |
| `cmd/xpfd/` | Daemon main binary |
| `cmd/cli/` | Remote CLI client binary |
| `userspace-xdp/` | XDP shim for AF_XDP packet steering (Rust/eBPF) |
| `userspace-dp/` | Rust AF_XDP userspace dataplane binary |
| `docs/` | Protocol docs, test plans, feature gaps |
| `test/incus/` | Test environment scripts and configs |

## Documentation

See `docs/` for detailed design documents:
- `sync-protocol.md` — Cluster session sync wire protocol and algorithms
- `fabric-cross-chassis-fwd.md` — Fabric link cross-chassis forwarding design
- `ha-cluster.conf` — Unified HA cluster config with `${node}` variable expansion
- `testing-procedures.md` — Test categories, procedures, and debugging tips
- `phases.md` — Development phase history (40+ sprints)
- `bugs.md` — Bug tracker with root cause analysis
- `optimizations.md` — Performance profiling and optimization notes
- `test_env.md` — Test topology and validation steps
- `feature-gaps.md` — vSRX feature parity tracking
- `userspace-dataplane-architecture.md` — Comprehensive userspace AF_XDP dataplane architecture
- `userspace-debug-map.md` — Active file/function map for userspace forwarding and debugging
- `xdp-io-uring-userspace-dataplane.md` — Original userspace dataplane design document
- `shared-umem-plan.md` — Cross-NIC shared UMEM design and validation plan
- `userspace-ha-validation.md` — HA failover validation procedures
- `userspace-perf-compare.md` — Throughput benchmarking methodology
- `userspace-dnat-plan.md` — Destination NAT implementation plan for userspace dataplane
- `userspace-dataplane-gaps.md` — Feature gap analysis: userspace vs eBPF dataplane

## Requirements

- Linux kernel 6.12+ (6.18+ recommended for full NAT64 support)
- Go 1.22+
- clang/llvm (for legacy BPF compilation and XDP shim generation)
- Rust stable (for the primary userspace dataplane)
- FRR (for routing protocol integration)
- strongSwan (for IPsec, optional)
- Kea (for DHCP server, optional)
