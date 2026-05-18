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
| Source NAT (pool mode) | Implemented with caveats | IPv4/IPv6 pool address and port allocation; wrong-family pools are skipped so later compatible rules can match. Global `source address-persistent` uses the documented userspace-v1 SHA-256 source-IP hash and is stable only within the AF_XDP backend, pool family, pool order, and pool size. Legacy eBPF and current DPDK use C-word IPv4 modulo / IPv6 lane-XOR selection, so new-flow pool address parity is not promised across backend rollback. Pool-mode rules omitted for missing pools, empty pools, or invalid port ranges are not a runtime fail-closed gate yet: the current `poll_descriptor.rs` source-NAT call sites can fall through to the default empty NAT decision and forward without SNAT. Per-pool `persistent-nat` is not a userspace-v1 runtime contract yet: the snapshot has no persistence-mode fields, Rust does not consult the Go `PersistentNATTable`, and the allocator has no live-port exhaustion counter. |
| Destination NAT | Implemented | Pre-expanded tuple snapshots from Go |
| Static NAT | Implemented | Bidirectional 1:1 translation |
| NAT64 | Implemented | Forward and reverse translation with reverse-session state |
| NPTv6 | Implemented | Stateless prefix translation |
| Firewall filters | Implemented | Filter snapshots and evaluation in Rust |
| Flow export | Implemented | Userspace flow export snapshot and runtime |
| Three-color policers | Implemented with caveats | srTCM/trTCM runtime, forwarding-path and flow-cache-hit metering, red drops for `then discard`, status/CLI/Prometheus counters. Sharded state, cross-snapshot continuity, non-drop color actions, and integration evidence remain #1375 follow-up work. |
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
| Screen behavior requiring SYN cookies | Gated; userspace screen runtime has fail-closed cookie challenge/ACK-validation/cache scaffolding, but no HA key publication or SYN-ACK/RST TX yet | #1374 |
| Port mirroring | Gated; partial runtime | #1376 still needs full path coverage and integration evidence before the gate is removed |

Port mirroring now has snapshot/wire plumbing plus a bounded forwarded-path
runtime slice that samples and queues discardable full-L2 mirror clones with
drop counters. The runtime coverage now includes the pending-forward path,
self-target flow-cache mirror surface, and deferred neighbor-resolution retry
path. The `deriveUserspaceCapabilities()` gate intentionally remains until
#1376 covers the remaining ingress/transmit surfaces and has integration
validation for mirror output fidelity and forwarding survival under mirror
pressure.

## Features That Still Use A Mixed Boundary

These are not "missing", but they are not pure userspace forwarding either:

| Area | Current boundary |
|------|------------------|
| SYN cookie flood protection | Legacy eBPF fallback until #1374 wires HA-safe secrets, bounded SYN-ACK/RST TX, counters/status, and removes the userspace capability gate |
| Kernel-owned traffic (ARP, local delivery, management, some non-IP) | cpumap or kernel pass-through from XDP |
| GRE / ESP / explicit early filters | Tail-call back into the legacy XDP pipeline |
| IPsec / XFRM handling | Userspace detects and punts to kernel/slow-path as needed |
| DataPlane control-plane contract | Userspace manager no longer embeds the legacy `dataplane.DataPlane`; a userspace `LegacyDataPlaneAdapter` owns old-interface compatibility while callers migrate. The manager still holds a named eBPF shim manager for XDP/map bootstrap state; tracked by #1381 |
| Dataplane event logging | Session open/close/update are emitted by userspace. Policy-deny, screen-drop, and filter-log frame types, RT_FLOW codec/Go decode, and Rust non-blocking producer/rate-limit/loss-accounting infrastructure are present; runtime producer call sites and end-to-end syslog evidence remain tracked by #1379. |
| `show system buffers` | Userspace helper-status rendering covers AF_XDP UMEM/TX capacity, CoS queued-byte capacity, active-session footer, neighbor/flow-cache counts, and worker queue pressure counters. #1380 is narrowed to the Phase 5 cleanup decision about whether operators need new helper capacity denominators for session-table, flow-cache, or neighbor-cache fill percentages before the legacy BPF-map surface is removed. |

## Retirement Blockers From The 2026-05-16 Audit

The current #1373 audit produced these tracked blockers:

| Issue | Blocker | Required before |
|-------|---------|-----------------|
| #1381 | Split or replace the BPF-shaped `dataplane.DataPlane` interface so userspace no longer embeds the eBPF manager for map-writer methods | Phase 3 build-system / Go removal |
| #1377 | Preserve userspace-v1 address-persistent SNAT pool selection with an explicit backend compatibility boundary, then finish per-pool `persistent-nat` semantics and allocation/exhaustion counters. #1385 landed deterministic userspace selection and snapshot omission for missing, empty, or invalid pool inputs, but runtime remains fail-open at the `poll_descriptor.rs` source-NAT call sites and does not provide persistent-NAT lease reuse or cross-backend new-flow parity. | Phase 4 BPF source removal |
| #1378 | Finish the policy-scheduler retirement contract after #1396 userspace propagation: hit-counter survival across scheduler snapshot rebuilds and strict missing-scheduler commit behavior landed in the 2026-05-17 closeout slice; remaining blocker is integration/failover validation evidence | Phase 4 BPF source removal |
| #1379 | Emit policy-deny, screen-drop, and filter-log dataplane events from userspace | Phase 4 BPF source removal |
| #1374 | Implement userspace SYN-cookie flood protection or an approved equivalent. #1393 and the 2026-05-17 runtime slice cover deterministic cookie codec/layout, snapshot propagation, fail-closed screen challenge selection, session-miss ACK validation, and a bounded validated-client cache. Lower-layer coverage in `userspace-dp/src/screen_tests.rs` pins 4-way validated-client cache replacement; poll-stage tests only pin the operational invalid-ACK drop/bypass semantics. Remaining: validated-client cache expiration semantics, secret-epoch rotation, bounded SYN-ACK TX, ACK RST emission, HA-safe secret publication/cache survivability, counters/status, integration/failover validation, and userspace capability gate removal. | Phase 4 BPF source removal |
| #1375 | Finish userspace RFC 2697/2698 three-color policer hardening: sharded/packed state decision, cross-snapshot counter continuity decision, non-drop color action handling, and integration/failover/performance evidence | Phase 4 BPF source removal |
| #1376 | Implement userspace port mirroring or explicitly retire the feature | Phase 4 BPF source removal |
| #1380 | Retire the remaining BPF-map-oriented `show system buffers` operator surface. Userspace now renders the bounded helper status that exists; only optional new helper capacity denominators for session-table / flow-cache / neighbor-cache fill remain undecided. | Phase 5 CLI / observability cleanup |

Recommended dependency order:

1. #1381 first, because it defines the control-plane interface boundary that
   every later removal phase depends on.
2. #1377 and #1379 next, because they are silent correctness or
   security-visibility regressions in configurations that may otherwise appear
   admitted. #1385 reduced #1377 risk, and the current contract documents the
   userspace-v1 selector plus mixed-backend rollback boundary, but per-pool
   `persistent-nat` and allocator exhaustion counters remain #1377 runtime
   gaps. #1378 is no longer missing basic userspace propagation after #1396,
   but its remaining counter/validation/evidence contract still blocks BPF
   source removal.
3. #1374 and #1376 before Phase 4, because these are explicit feature gaps
   currently protected by the legacy eBPF fallback. Keep #1375 on the Phase 4
   list for validation and hardening evidence, not as a capability gate.
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
   regressions; keep #1385 plus the userspace-v1 fixtures as evidence of the
   current AF_XDP SNAT pool selector, not full persistent-NAT parity. Keep
   #1378 open for the remaining policy-scheduler counter/validation/evidence
   contract after #1396.
3. close #1374 and #1376 before any BPF source removal, and finish the #1375
   hardening/evidence checklist. The three-color capability gate is removed
   only for the current color-blind `then discard` slice; color-aware and
   non-drop treatments stay fail-closed.
4. carry the narrowed #1380 denominator decision into Phase 5; the current
   userspace command already avoids BPF-map fallback when helper status is
   available
5. continue correctness and performance hardening on the active AF_XDP fast path
