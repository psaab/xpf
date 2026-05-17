# Userspace Dataplane: Current Capability Gate

This document tracks the current admission boundary on `master` for the Rust
AF_XDP userspace dataplane. It is not a full bug tracker and it is not a
historical branch plan. For active debugging entry points, use
[`userspace-debug-map.md`](userspace-debug-map.md).

Last updated: 2026-05-17

## Deprecation Context

Issue #1373 retires the legacy eBPF dataplane in staged phases. As of Phase 1,
the Rust AF_XDP userspace dataplane is the primary/default target for
dataplane development and routine validation. Phase 1 is still documentation
and migration-targeting work only: no BPF source, bpf2go bindings, loader code,
test targets, or CLI surfaces are removed in this phase. Until the blockers
below are closed, the legacy eBPF dataplane remains present as the
compatibility and rollback path for configurations the AF_XDP userspace
dataplane cannot yet own.

## Implemented In The Current Runtime

These capabilities exist in the current Rust userspace dataplane code path:

| Feature | Current state | Notes |
|---------|---------------|-------|
| Stateful forwarding | Implemented | Per-worker sessions plus shared session tables |
| Zone + global policies | Implemented | Address and application terms are pre-expanded by the daemon |
| Application matching | Implemented | Protocol + port terms, including expanded multi-term apps |
| Source NAT (interface mode) | Implemented | IPv4 and IPv6 egress interface rewrite |
| Source NAT (pool mode) | Implemented with caveat | IPv4/IPv6 pool address and port allocation; wrong-family pools are skipped so later compatible rules can match. `address-persistent` uses a userspace-v1 deterministic SHA-256 source-IP hash that intentionally differs from legacy eBPF IPv4 modulo / IPv6 lane-XOR selection and from DPDK allocator internals until #1377 defines a shared cross-backend contract. |
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
[`pkg/dataplane/userspace/manager.go`](../pkg/dataplane/userspace/manager.go):

| Feature/config shape | Gate status | Retirement blocker |
|----------------------|-------------|--------------------|
| Unsupported policy shapes | Gated | Address/application expansion must succeed for userspace |
| Screen behavior requiring SYN cookies | Gated | #1374 |
| Three-color policers | Gated | #1375 |
| Port mirroring | Gated | #1376 |

## Features That Still Use A Mixed Boundary

These are not "missing", but they are not pure userspace forwarding either:

| Area | Current boundary |
|------|------------------|
| SYN cookie flood protection | Legacy eBPF fallback |
| Kernel-owned traffic (ARP, local delivery, management, some non-IP) | cpumap or kernel pass-through from XDP |
| GRE / ESP / explicit early filters | Tail-call back into the legacy XDP pipeline |
| IPsec / XFRM handling | Userspace detects and punts to kernel/slow-path as needed |
| DataPlane control-plane contract | Userspace manager no longer embeds the legacy `dataplane.DataPlane`; a userspace `LegacyDataPlaneAdapter` owns old-interface compatibility while callers migrate. The manager still holds a named eBPF shim manager for XDP/map bootstrap state; tracked by #1381 |
| Dataplane event logging | Session open/close/update are emitted by userspace; policy-deny, screen-drop, and filter-log events still depend on the legacy BPF ring buffer; tracked by #1379 |
| `show system buffers` | Userspace helper-status rendering landed in #1386 for AF_XDP UMEM/TX capacity. #1380 still tracks the retirement gate for removing legacy BPF-map buffer reporting and settling the CLI / observability cleanup. |

## Retirement Blockers From The 2026-05-16 Audit

The current #1373 audit produced these tracked blockers:

| Issue | Blocker | Required before |
|-------|---------|-----------------|
| #1381 | Split or replace the BPF-shaped `dataplane.DataPlane` interface so userspace no longer embeds the eBPF manager for map-writer methods | Phase 3 build-system / Go removal |
| #1377 | Preserve address-persistent SNAT pool selection with an approved cross-backend contract. #1385 landed userspace-v1 deterministic selection and fail-closed pool admission, but does not close cross-backend parity by itself. | Phase 4 BPF source removal |
| #1378 | Finish the policy-scheduler retirement contract after #1396 userspace propagation: hit-counter survival across scheduler snapshot rebuilds, strict missing-scheduler commit behavior, and integration/failover validation | Phase 4 BPF source removal |
| #1379 | Emit policy-deny, screen-drop, and filter-log dataplane events from userspace | Phase 4 BPF source removal |
| #1374 | Implement userspace SYN-cookie flood protection or an approved equivalent | Phase 4 BPF source removal |
| #1375 | Implement userspace RFC 2697/2698 three-color policers | Phase 4 BPF source removal |
| #1376 | Implement userspace port mirroring or explicitly retire the feature | Phase 4 BPF source removal |
| #1380 | Retire the remaining BPF-map-oriented `show system buffers` operator surface now that #1386 provides userspace helper-status reporting. | Phase 5 CLI / observability cleanup |

Recommended dependency order:

1. #1381 first, because it defines the control-plane interface boundary that
   every later removal phase depends on.
2. #1377 and #1379 next, because they are silent correctness or
   security-visibility regressions in configurations that may otherwise appear
   admitted. #1385 reduced #1377 risk but did not close the cross-backend
   address-persistent contract. #1378 is no longer missing basic userspace
   propagation after #1396, but its remaining counter/validation/evidence
   contract still blocks BPF source removal.
3. #1374, #1375, and #1376 before Phase 4, because these are explicit feature
   gaps currently protected by the legacy eBPF fallback.
4. #1380 in Phase 5, after the dataplane boundary is settled but before the
   remaining operator-facing BPF map surface disappears.

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

1. resolve #1381 so userspace is no longer structurally coupled to the eBPF
   manager contract
2. fix #1377 and #1379 to remove silent correctness and visibility
   regressions; keep #1385 as evidence of the current userspace-v1 SNAT pool
   behavior, not full cross-backend parity. Keep #1378 open for the remaining
   policy-scheduler counter/validation/evidence contract after #1396.
3. close #1374, #1375, and #1376 before any BPF source removal
4. carry #1380 into the Phase 5 CLI / observability cleanup now that #1386
   supplies userspace buffer rendering
5. continue correctness and performance hardening on the active AF_XDP fast path
