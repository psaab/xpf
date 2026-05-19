# Userspace Dataplane: Current Capability Gate

This document tracks the current admission boundary on `master` for the Rust
AF_XDP userspace dataplane. It is not a full bug tracker and it is not a
historical branch plan. For active debugging entry points, use
[`userspace-debug-map.md`](userspace-debug-map.md).

Last updated: 2026-05-19

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
| Policy schedulers | Implemented with evidence pending | Scheduled-policy `scheduler_name` and `inactive` bits are published in userspace snapshots, old helper protocol mismatches disarm forwarding, missing policy-scheduler references are commit errors, and Rust hit counters survive active/inactive snapshot rebuilds by stable rule ID. #1378 is narrowed to collecting live userspace HA artifacts with `test/incus/policy_scheduler_validate.py`. |
| Application matching | Implemented | Protocol + port terms, including expanded multi-term apps |
| Source NAT (interface mode) | Implemented | IPv4 and IPv6 egress interface rewrite |
| Source NAT (pool mode) | Implemented with caveats | IPv4/IPv6 pool address and port allocation. Global `source address-persistent` uses the documented userspace-v1 SHA-256 source-IP hash and is stable only within the AF_XDP backend, pool family, pool order, and pool size. Legacy eBPF and current DPDK use C-word IPv4 modulo / IPv6 lane-XOR selection, so new-flow pool address parity is not promised across backend rollback. Pool-mode rules with missing pools, empty pools, invalid port ranges, malformed addresses, or no address for the packet family now fail-closed at the `poll_descriptor.rs` source-NAT call sites before session creation or forwarding, with recent-exception reasons such as `source_nat_pool_missing`, `source_nat_pool_empty`, and `source_nat_pool_invalid_port_range`. Per-pool `persistent-nat` is not a userspace-v1 runtime contract yet: the snapshot has no persistence-mode fields, Rust does not consult the Go `PersistentNATTable`, and the allocator has no live-port exhaustion counter. |
| Destination NAT | Implemented | Pre-expanded tuple snapshots from Go |
| Static NAT | Implemented | Bidirectional 1:1 translation |
| NAT64 | Implemented | Forward and reverse translation with reverse-session state |
| NPTv6 | Implemented | Stateless prefix translation |
| Firewall filters | Implemented | Filter snapshots and evaluation in Rust |
| Flow export | Implemented | Userspace flow export snapshot and runtime |
| Three-color policers | Implemented with caveats | srTCM/trTCM runtime, forwarding-path and flow-cache-hit metering, red drops for `then discard`, status/CLI/Prometheus counters, and compatible in-process snapshot continuity. Unsupported color-aware, non-`discard`, and malformed snapshots now fail closed in Rust if they bypass Go admission. Sharded state, HA/restart continuity decision, full non-drop action propagation, and integration evidence remain #1375 follow-up work. |
| TCP MSS clamping | Implemented | Flow snapshot fields are delivered and used in Rust |
| Embedded ICMP NAT reversal | Implemented | Includes reverse-session repair paths |
| Configurable session timeouts | Implemented | Snapshot-driven timeouts in `session.rs` |
| VLAN handling | Implemented | Ingress VLAN tracking and egress tagging |
| Route and neighbor lookup | Implemented | Per-table routes, neighbor cache, next-table support |
| HA state ingestion | Implemented | Helper receives RG active/watchdog state |
| Session delta export | Implemented | Rust helper exports open/close deltas back to Go |

## Gated Or Evidence-Only Before BPF Source Removal

These are the remaining explicit configuration gates, plus the runtime-admitted
features that still need operator evidence before BPF source removal. The
explicit gates live in
[`pkg/dataplane/userspace/manager.go`](../pkg/dataplane/userspace/manager.go).

| Feature/config shape | Userspace status | Retirement blocker |
|----------------------|-------------|--------------------|
| Unsupported policy shapes | Gated | Address/application expansion must succeed for userspace |
| Screen behavior requiring SYN cookies | Gated; userspace screen runtime has fail-closed cookie challenge/ACK-validation/cache semantics and status counters, but no HA key publication or SYN-ACK/RST TX yet | #1374 |
| Port mirroring | Supported; evidence pending | #1376 still needs mirror-fidelity and pressure evidence before BPF source removal |

Port mirroring now has snapshot/wire plumbing plus a bounded runtime slice
that samples and queues discardable full-L2 mirror clones with drop counters.
Runtime coverage includes the pending-forward path, self-target flow-cache
mirror surface, deferred neighbor-resolution retry path, CoS-bound reserve
handling, and mirror-specific counter attribution. The
`deriveUserspaceCapabilities()` gate has been removed; #1376 remains open for
integration evidence that tcpdump on the mirror output sees full-frame clones
at the expected sample rate and that primary forwarding survives mirror
pressure.

## Features That Still Use A Mixed Boundary

These are not "missing", but they are not pure userspace forwarding either:

| Area | Current boundary |
|------|------------------|
| SYN cookie flood protection | Legacy eBPF fallback until #1374 wires HA-safe secrets, bounded SYN-ACK/RST TX, integration/failover validation, and removes the userspace capability gate. Userspace now reports selected challenge/no-secret/valid-ACK/invalid-ACK/bypass counters, but does not report SYN-ACKs sent until TX exists. |
| Kernel-owned traffic (ARP, local delivery, management, some non-IP) | cpumap or kernel pass-through from XDP |
| GRE / ESP / explicit early filters | Tail-call back into the legacy XDP pipeline |
| IPsec / XFRM handling | Userspace detects and punts to kernel/slow-path as needed |
| DataPlane control-plane contract | Userspace manager no longer embeds the legacy `dataplane.DataPlane`; a userspace `LegacyDataPlaneAdapter` owns old-interface compatibility while callers migrate. Operator metadata reads in API/gRPC/CLI/daemon now use `LastApplyResult()` instead of `LastCompileResult()`, with a canary preventing those surfaces from regressing to compile-result metadata. GC and HA session sync now use `SessionStore`/`Telemetry`. The manager still holds a named eBPF shim manager for XDP/map bootstrap state, and API/gRPC/CLI session/counter readers plus daemon control paths still need to move fully to domain interfaces; tracked by #1381 |
| Dataplane event logging | Session open/close/update are emitted by userspace. Policy-deny, screen-drop, logged routing-instance filter hits, non-PBR input filter logs, output filter logs, cached output-filter hits, and lo0 filter logs now enqueue RT_FLOW frames through the non-blocking Rust event-stream producer with existing per-event rate-limit/loss accounting. Go decode/status handling feeds raw userspace RT_FLOW frames through the same `EventReader.ProcessRawEvent` syslog/local-log path as eBPF, with a deterministic UDP syslog fanout harness for policy deny, screen drop, and filter log. Policy-deny events now carry the snapshot's compiled numeric policy ID; filter-log events carry filter/term/action identity from the matched compiled term. Remaining #1379 evidence is live userspace-cluster syslog capture, including deny-storm starvation checks, if Phase 4 requires operator artifacts beyond the deterministic local harness. |
| `show system buffers` | Userspace helper-status rendering covers AF_XDP UMEM/TX capacity, CoS queued-byte capacity, active-session footer, neighbor/flow-cache counts, and worker queue pressure counters. The Phase 5 denominator decision is explicit: session-table, flow-cache, and neighbor-cache values remain counters, not fill percentages, until the helper publishes bounded capacity fields. A formatter test pins that these dynamic counts cannot move into the utilization table without real denominators. |

## Retirement Blockers From The 2026-05-16 Audit

The current #1373 audit produced these tracked blockers:

| Issue | Blocker | Required before |
|-------|---------|-----------------|
| #1381 | Split or replace the BPF-shaped `dataplane.DataPlane` interface so userspace no longer embeds the eBPF manager for map-writer methods. Current progress: userspace no longer embeds the legacy interface, neutral `RuntimeDataPlane` domains exist, operator metadata reads use `ApplyResult`, and GC plus HA session sync use `SessionStore`/`Telemetry` for session/counter work; remaining work is API/gRPC/CLI session/counter readers, daemon control paths, userspace-specific diagnostics/control adapters, and the final userspace shim removal. | Phase 3 build-system / Go removal |
| #1377 | Preserve userspace-v1 address-persistent SNAT pool selection with an explicit backend compatibility boundary, then finish per-pool `persistent-nat` semantics and allocation/exhaustion counters. The current runtime fails closed for source-NAT pool rules with missing pools, empty pools, invalid pool inputs, wrong-family-only pools, or allocator failure at the `poll_descriptor.rs` source-NAT call sites, but it still does not provide persistent-NAT lease reuse, live-port exhaustion accounting, or cross-backend new-flow parity. | Phase 4 BPF source removal |
| #1378 | Finish the policy-scheduler retirement contract after #1396 userspace propagation: hit-counter survival across scheduler snapshot rebuilds and strict missing-scheduler commit behavior landed in the 2026-05-17 closeout slice. The 2026-05-18 closeout slice adds a deterministic userspace evidence checker and pins the non-eBPF apply path; remaining blocker is only the live HA artifact capture accepted by `test/incus/policy_scheduler_validate.py`. | Phase 4 BPF source removal |
| #1379 | Complete dataplane event closeout: policy-deny, screen-drop, logged PBR filter hits, non-PBR input/output/lo0 filter logs, cached output-filter logs, policy numeric IDs, and filter/term identities now emit from userspace through the RT_FLOW stream. Deterministic Go syslog fanout coverage exists for policy deny, screen drop, and filter log. Remaining blocker is live userspace-cluster syslog evidence, including deny-storm starvation checks, if #1373 Phase 4 requires external artifacts. | Phase 4 BPF source removal |
| #1374 | Implement userspace SYN-cookie flood protection or an approved equivalent. #1393, the 2026-05-17 runtime slice, and the 2026-05-18 closeout slice cover deterministic cookie codec/layout, snapshot propagation, fail-closed screen challenge selection, session-miss ACK validation, bounded validated-client cache behavior, TTL-bound single-use validated-client expiration, current/previous cookie-epoch ACK validation, explicit validated-client bypass verdicts, userspace helper status counters, and legacy global sync for valid/invalid/bypass counters. Remaining: bounded SYN-ACK TX and sent/budget counters, ACK RST emission, HA-safe secret publication/cache survivability, integration/failover validation, and userspace capability gate removal. | Phase 4 BPF source removal |
| #1375 | Finish userspace RFC 2697/2698 three-color policer hardening. The current runtime admits the color-blind `then discard` slice, fails closed for unsupported snapshot shapes that bypass Go admission, and preserves token/counter state across compatible in-process snapshot refreshes. Remaining work: sharded/packed state decision, HA/restart continuity decision, full non-drop color action propagation, and integration/failover/performance evidence | Phase 4 BPF source removal |
| #1376 | Finish userspace port mirroring evidence. Snapshot/wire plumbing, bounded runtime delivery, pending-forward, self-target flow-cache, deferred-neighbor retry, CoS reserve handling, counter attribution, and capability admission now exist. Remaining work is mirror-fidelity evidence and forwarding survival under mirror pressure. | Phase 4 BPF source removal |
| #1380 | Retire the remaining BPF-map-oriented `show system buffers` operator surface. Userspace now renders the bounded helper status that exists and intentionally keeps session-table / flow-cache / neighbor-cache as counters rather than synthetic utilization rows until the helper exports true capacity fields. | Phase 5 CLI / observability cleanup |

Recommended dependency order:

1. #1381 first, because it defines the control-plane interface boundary that
   every later removal phase depends on.
2. #1377 and #1379 next, because they are silent correctness or
   security-visibility regressions in configurations that may otherwise appear
   admitted. #1377 now has fail-closed pool runtime handling for unusable
   pool snapshots, and the current contract documents the userspace-v1 selector
   plus mixed-backend rollback boundary, but per-pool `persistent-nat` and
   allocator exhaustion counters remain #1377 runtime gaps. #1378 is no longer
   missing basic userspace propagation after #1396,
   but its remaining counter/validation/evidence contract still blocks BPF
   source removal.
3. #1374 and #1376 before Phase 4. #1374 is still protected by the legacy eBPF
   fallback; #1376 has bounded userspace runtime admission and remains listed
   for mirror-fidelity plus pressure-survival evidence before BPF source
   removal. Keep #1375 on the Phase 4 list for validation and hardening
   evidence, not as a capability gate. #1378 now needs the scripted scheduler
   artifact capture only; no additional scheduler runtime code is known from
   the current audit.
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
   #1378 on the closeout list until the scripted userspace HA scheduler
   evidence artifact set is captured.
3. close #1374 and collect the remaining #1376 mirror evidence before any BPF
   source removal, and finish the #1375 hardening/evidence checklist. The
   three-color capability gate is removed only for the current color-blind
   `then discard` slice with compatible in-process snapshot continuity;
   color-aware and non-drop treatments stay
   fail-closed in both Go admission and Rust snapshot parsing.
4. carry #1380 into Phase 5 only if operators need new helper capacity fields;
   the current userspace command already avoids BPF-map fallback when helper
   status is available and does not synthesize percentages for dynamic tables
5. continue correctness and performance hardening on the active AF_XDP fast path
