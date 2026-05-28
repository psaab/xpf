# Codex plan review — round 1 (#1636)

**Task ID**: task-mpprvkz5-63418a
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` @ `ee82b880b`

## VERDICT: PLAN-NEEDS-MAJOR

## Findings (verbatim from Codex)

1. Kernel rate-limit claim is basically correct. In `net/core/neighbour.c:1199-1275`, `__neigh_event_send()` only sets `immediate_probe` when transitioning into `NUD_INCOMPLETE`; if the entry is already `NUD_INCOMPLETE`, it queues the skb and returns. `neigh_timer_handler()` then schedules further probes using `RETRANS_TIME` at `net/core/neighbour.c:1156-1161`. So repeated userspace `sendto()` calls do not force fresh ARPs inside `retrans_time`. Option A is therefore not the real lever unless it changes kernel retrans timing or bypasses kernel NUD.

2. B alone does not support a hard `<=200ms` gate if `retrans_time_ms=250`. If the first ARP/NS is missed, the next kernel solicit is no earlier than ~250ms, before any handshake work. C is what can make the data SYN fast, but only if warming completes before the test connection. The plan needs to state that explicitly.

3. C has an unresolved failover hazard. A warm pass at `refresh_runtime_snapshot()` tail can overlap RG promotion and VRRP GARP bursts. Even if harmless in the common case, the plan must define ordering/debounce after `becomeMaster()`/config apply, or prove from `pkg/cluster` and `pkg/vrrp` that warm traffic cannot race upstream FIB/ARP convergence.

4. The warm-pass cost model is not acceptable as written. "Unique next-hop dedup per snapshot" does not bound repeated snapshots. At 10 snapshots/s and 100 routes, the plan still permits 1000 socket/send/close attempts per second during churn. It needs a persistent worker, coalescing, max rate, generation collapse, and recent-warm cache.

5. PR sequencing should change. Ship B first as a sysctl-only PR, measure cold connect and neighbour timings, then decide whether C is still justified. B is low-risk and directly changes the kernel timer that gates ARP retries; C is code, HA, test, and operator surface.

6. Rejection of D is sound for the drop-based version. Linux `TCP_TIMEOUT_INIT` is `1*HZ` in `include/net/tcp.h:2486`; dropping a queued SYN at ~800ms means the first TCP retransmit at ~1s can enter the same unresolved path and be dropped before the next retransmit window. D does not make the cold path deterministic.

7. Tunnel/IPsec warming is underspecified. GRE underlay warming is reasonable only for the resolved physical underlay next-hop, not inner tunnel destinations. IPsec can have policy/acquire side effects if the warm packet is ordinary payload. This needs route/neighbour-state-driven selection, skip rules for NOARP/point-to-point/tunnel-inner paths, and explicit xfrm handling.

8. Testability and CLI fit are not proven. I could not inspect the requested local worktree in this session because command execution is unavailable, so `coordinator/tests.rs`, `Coordinator::refresh_runtime_snapshot()`, `pkg/cmdtree/tree.go`, and VRRP sequencing still need real file-line validation before this can become PLAN-READY.

## Recommendation

Require revision. Keep B, split it into the first PR, and make C conditional on measured residual latency. If C remains, redesign it as a bounded, debounced warm worker with HA ordering, route-type skip rules, injected test seams, and explicit acceptance criteria that distinguish "first connection after completed warm" from "first packet while warming is still in flight."

Sources used: Linux neighbour source via kernel mirror/codebrowser, and Linux TCP constants in `include/net/tcp.h`.

## Session

Codex session ID: 019e6fa6-9065-70f0-bd0a-07e222290e7e
