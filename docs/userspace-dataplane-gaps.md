# Userspace Dataplane: Current Capability Gate

This document tracks the current admission boundary on `master` for the Rust
AF_XDP userspace dataplane. It is not a full bug tracker and it is not a
historical branch plan. For active debugging entry points, use
[`userspace-debug-map.md`](userspace-debug-map.md).

Last updated: 2026-05-16

## Implemented In The Current Runtime

These capabilities exist in the current Rust userspace dataplane code path:

| Feature | Current state | Notes |
|---------|---------------|-------|
| Stateful forwarding | Implemented | Per-worker sessions plus shared session tables |
| Zone + global policies | Implemented | Address and application terms are pre-expanded by the daemon |
| Application matching | Implemented | Protocol + port terms, including expanded multi-term apps |
| Source NAT (interface mode) | Implemented | IPv4 and IPv6 egress interface rewrite |
| Source NAT (pool mode) | Implemented | IPv4/IPv6 pool address and port allocation; `address-persistent` uses a deterministic source-IP hash |
| Destination NAT | Implemented | Pre-expanded tuple snapshots from Go |
| Static NAT | Implemented | Bidirectional 1:1 translation |
| NAT64 | Implemented | Forward and reverse translation with reverse-session state |
| NPTv6 | Implemented | Stateless prefix translation |
| Firewall filters | Implemented | Filter snapshots and evaluation in Rust |
| Flow export | Implemented | Userspace flow export snapshot and runtime |
| TCP MSS clamping | Implemented | Flow snapshot fields are delivered and used in Rust |
| Embedded ICMP NAT reversal | Implemented | Includes reverse-session repair paths |
| Configurable session timeouts | Implemented | Snapshot-driven timeouts in `session.rs` |
| VLAN handling | Implemented | Ingress VLAN tracking and egress tagging |
| Route and neighbor lookup | Implemented | Per-table routes, neighbor cache, next-table support |
| HA state ingestion | Implemented | Helper receives RG active/watchdog state |
| Session delta export | Implemented | Rust helper exports open/close deltas back to Go |

## Still Gated By `deriveUserspaceCapabilities()`

These are the remaining explicit configuration gates in
[`pkg/dataplane/userspace/manager.go`](/home/ps/git/codex-xpf/pkg/dataplane/userspace/manager.go):

| Feature/config shape | Gate status | Reason |
|----------------------|-------------|--------|
| Unsupported policy shapes | Gated | Address/application expansion must succeed for userspace |
| Screen behavior requiring SYN cookies | Gated | SYN-cookie behavior remains a legacy eBPF capability |
| Three-color policers | Gated | Simple filters are supported; three-color policers are not |
| Port mirroring | Gated | No userspace mirroring path |

## Features That Still Use A Mixed Boundary

These are not "missing", but they are not pure userspace forwarding either:

| Area | Current boundary |
|------|------------------|
| SYN cookie flood protection | Legacy eBPF fallback |
| Kernel-owned traffic (ARP, local delivery, management, some non-IP) | cpumap or kernel pass-through from XDP |
| GRE / ESP / explicit early filters | Tail-call back into the legacy XDP pipeline |
| IPsec / XFRM handling | Userspace detects and punts to kernel/slow-path as needed |

## What This Document Does Not Mean

A feature being "implemented" here means the runtime has code for it. It does
not guarantee:

- that every configuration shape using the feature is currently admitted
- that every path is already hardened for HA failover
- that current performance is at parity with the legacy dataplane
- that there are no active correctness bugs in the forwarding path

Those are separate questions. Use:

- [`userspace-ha-validation.md`](userspace-ha-validation.md)
- [`userspace-perf-compare.md`](userspace-perf-compare.md)
- [`userspace-debug-map.md`](userspace-debug-map.md)

## Actual Fallback Mechanisms

There are two distinct fallback boundaries:

1. **Compile-time / reconcile-time gate**
   - The Go manager chooses `xdp_userspace_prog` or `xdp_main_prog`
     depending on `deriveUserspaceCapabilities()`.

2. **Runtime XDP decision**
   - Even when `xdp_userspace_prog` is active, the XDP shim can still:
     - redirect to AF_XDP
     - send kernel-owned traffic to cpumap / kernel
     - tail-call back into the legacy XDP pipeline for explicit fallback reasons
     - drop on dead/missing userspace bindings to fail closed

## Priority Work

The highest-value remaining work on current `master` is:

1. close the remaining SYN-cookie-dependent screen gap
2. implement three-color policer support
3. implement port mirroring
4. continue correctness and performance hardening on the active AF_XDP fast path
