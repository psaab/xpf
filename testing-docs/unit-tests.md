# Unit Tests

## Overview

Unit tests validate individual components in isolation. They run fast (< 30s total) and must pass before any commit.

## Go Tests (26 packages, 880+ tests)

```bash
make test
```

### Key Packages

| Package | Tests | What's Covered |
|---------|-------|----------------|
| `pkg/config` | ~250 | Junos parser (hierarchical + flat set), AST, typed config, ${node} expansion |
| `pkg/dataplane` | ~80 | BPF map compilation, zone/policy/NAT/screen map entries, struct alignment |
| `pkg/dataplane/userspace` | ~50 | Userspace snapshot compilation, forwarding state, session map keys |
| `pkg/cluster` | ~100 | State machine (election, weight, failover), session sync protocol |
| `pkg/vrrp` | ~40 | VRRPv3 state machine, advertisement encoding, preempt logic |
| `pkg/frr` | ~20 | FRR config generation, managed sections |
| `pkg/routing` | ~30 | VRF, GRE tunnels, XFRM, rib-group leaking, ip rules |
| `pkg/networkd` | ~20 | .link/.network file generation, stale cleanup |
| `pkg/logging` | ~25 | Ring buffer reader, syslog formatting, event buffer |
| `pkg/ra` | ~10 | RA sender config diff, startup burst |
| `pkg/cli` | ~15 | Command resolution, prefix matching, pipe filters |
| `pkg/cmdtree` | ~15 | Tree structure, dynamic completion, help formatting |
| `pkg/grpcapi` | ~10 | gRPC server, protobuf bindings |
| `pkg/api` | ~20 | HTTP REST API, Prometheus collector |
| `pkg/flowexport` | ~5 | NetFlow v9 template encoding |
| `pkg/snmp` | ~5 | ifTable MIB responses |

### Running Individual Packages

```bash
go test -v ./pkg/config/...       # Config parser tests only
go test -v ./pkg/cluster/...      # Cluster state machine
go test -run TestFailover ./pkg/cluster/...  # Single test
```

## Rust Tests (356 tests)

```bash
cd userspace-dp && cargo test
```

### Key Test Areas

| Module | Tests | What's Covered |
|--------|-------|----------------|
| `afxdp.rs` | ~250 | Session lookup, forwarding resolution, NAT reversal, flow cache, embedded ICMP, policy evaluation |
| `afxdp/frame.rs` | ~60 | Frame rewrite (in-place + copy), checksum validation, VLAN push/pop, apply_rewrite_descriptor |
| `afxdp/session_glue.rs` | ~20 | Session key construction, reverse keys, NAT session publishing |
| `afxdp/icmp_embed.rs` | ~15 | Embedded ICMP parsing, NAT match, frame rebuild |
| `session.rs` | ~5 | Session table, timeout, GC |
| `filter.rs` | ~5 | Firewall filter matching |

### Running Specific Tests

```bash
cargo test apply_descriptor          # Descriptor rewrite tests
cargo test embedded_icmp             # Embedded ICMP tests
cargo test forwarding_resolution     # FIB/neighbor resolution
cargo test rewrite_forwarded_frame   # Frame rewrite + checksum
```

## What Must Pass Before Commit

1. `make test` — all Go tests
2. `cd userspace-dp && cargo test` — all Rust tests
3. `make build` — Go daemon compiles
4. `cargo build --release` — Rust helper compiles
5. `bash pkg/dataplane/build-userspace-xdp.sh` — XDP shim compiles and refreshes the embedded object (if changed)

For userspace dataplane changes, build-only checks are not enough. Continue
with the runtime validation in:

- [userspace-dataplane.md](userspace-dataplane.md)
- [ha-cluster.md](ha-cluster.md)
- [performance.md](performance.md)
