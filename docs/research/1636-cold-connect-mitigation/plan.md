# #1636 cold-connect / neighbor-resolution gap — research plan

**Status**: DRAFT v6 — revised after round-5 reviewer findings (HA per-RG, dual-stack sysctl, cached-once)
**Base SHA**: `dbfbf680cc82` (origin/master @ 2026-05-28)
**Branch**: `research/1636-cold-connect-mitigation`
**Scope**: research-only, no production source edits, no PR

## Changelog since v5

| # | Round-5 finding | Resolution |
|---|------------------|------------|
| AGY r5 #1 (MEDIUM) | HA architecture mismatch: `ha.is_active()` is placeholder; real arch is per-RG via `HAGroupRuntime::is_forwarding_active(now_secs)` | §7 + §9: `WarmItem` carries `rg_id`; queue_warm_pass + warmer pre-fire both check per-RG via `owner_rg_for_flow` + `HAGroupRuntime::is_forwarding_active` |
| Codex r5 #1 + AGY r5 #3 (LOW) | Sysctl validation must read BOTH IPv4 and IPv6 retrans_time_ms; fail closed on any value >250 or parse error | §7 PR-3 section reads both sysctls + takes max; fails closed |
| AGY r5 #2 (LOW) | Sysctl read must be cached at init in a `OnceLock`, not done in hot paths | §7 explicit OnceLock pattern |

## Changelog since v4

| # | Round-4 finding | Resolution |
|---|------------------|------------|
| Codex r4 #1 / AGY r4 #1 | HA demotion + mutex poisoning leave silent in-flight warming | §7 worker re-checks `ha.is_active()` AND generation immediately before fire; mutex `.expect()` on poison (lets worker die loudly so channel breaks) |
| Codex r4 #2 | Generation bump must be per ADMITTED sweep, not every `queue_warm_pass()` call | §7 generation bump moves AFTER the 1s snapshot rate-limit check |
| Codex r4 #3 / AGY r4 #3 | Disconnected log floods under route churn | `warned_disconnect: AtomicBool` once-only transition log |
| Codex r4 #4 | §10 "first-probe-LOST" label imprecise | §10 renamed "initial-resolution-train-failed"; sustained-loss note added |
| Codex r4 #5 | IPv6 NDP warming must be explicit | §7 notes `trigger_kernel_arp_probe()` already handles both AF_INET ICMP + AF_INET6 ICMPv6 in source (`userspace-dp/src/afxdp/neighbor.rs:36`) — confirmed dual-stack |
| AGY r4 #2 | D=800ms is operational hazard if PR-1 sysctl fails to apply at runtime | §7 / PR-3 adds runtime sysctl validation; if `retrans_time_ms > 250`, fall back to 2000ms timeout |

## Changelog v3 → v4

| # | Round-3 finding | Resolution |
|---|------------------|------------|
| AGY r3 #1 | Disconnect vs Full distinction + production-level error log + Prometheus exposure | §7 worker error handling expanded; warm_drops + warm_disconnected counters; production-level log on disconnect |
| AGY r3 #2 | GC bypass under continuous load (Timeout path never hit) | §7 GC check runs on EVERY iteration (idle + dequeue), keyed off `last_gc_ns` |
| AGY r3 #3 | Link UP transition needs to clear `last_probed_at` for ifindex | §9 invariant 7 expanded; new `Coordinator::on_link_up(ifindex)` |
| AGY r3 #4 | D=800ms is mathematically superior to D=700ms (kernel state machine async; late resolution preservation) | §5.1 + §9 + PR-3 reverted to 800ms |

## Changelog v2 → v3

| # | Round-2 finding | Resolution |
|---|------------------|------------|
| Codex r2 #3 / AGY r2 #1 / SMR r2 #9 | Generation collapse + latest-snapshot coalescing needed | §7 adds `warm_generation: AtomicU64` + per-item generation tag; worker drops stale items on dequeue |
| Codex r2 #4 / SMR r2 #4 | HA invariant must say warm pass runs only after RG promote commit | §9 invariant 2 expanded |
| AGY r2 #2 / SMR r2 #4 | Clear `last_probed_at` on RG-promote (avoid transient down lockout) | §9 invariant 7 added |
| AGY r2 #3 / SMR r2 #6 | GC prune `last_probed_at` entries older than 5min | §7 warmer-loop adds prune on idle-timeout |
| Codex r2 #5 / SMR r2 #2 | §10 latency derivation qualifications | §10 tightened |
| Codex r2 #6 / SMR r2 #10 | Document kernel ucast/mcast/app_solicit defaults; affects D timing choice | §5.1 added; D rationale tightened |
| AGY r2 #1 / SMR r2 #11 | Channel-disconnect telemetry | §7 adds bounded-channel + log on try_send Err + counter |
| AGY r2 #4 / SMR r2 #12 | Warmer worker fires once per (key, gen); no userspace retry needed | §7 explicit framing |

## Changelog v1 → v2

| # | Round-1 finding | Resolution |
|---|------------------|------------|
| Codex r1 #1 / AGY r1 #5 | Kernel rate-limit claim is correct; option A demoted | Re-stated §5 to confirm A is heartbeat-only; A removed from recommended set |
| Codex r1 #5 | Ship B first as sysctl-only PR, measure, then decide C | Adopted: §13 now sequences as B-PR-1, then C-PR-2 |
| AGY r1 #2 / SMR r1 #3 | Option D rejection was wrong; per-packet timestamping means SYN #2 gets fresh window | Reversed rejection of D; added D as a tier-2 lever paired with B |
| AGY r1 #4 / Codex r1 #2 / SMR r1 #2 | B-only gate-failure trap; first probe can be lost on zero-copy XSK-owned TX queues | §6 made explicit; B alone does not meet 200ms gate; C is mandatory for the gate |
| AGY r1 #1 / Codex r1 #4 / SMR r1 #6 | Warm-pass cost model under config storm + dead next-hops can FD-exhaust | §6 redesigned: rate-limited `last_probed_at` map in `NeighborManager` (5s per (ifindex, hop)); also coalesce snapshots to max 1 warm sweep/s |
| AGY r1 #3 / Codex r1 #7 / SMR r1 #5 | Tunnel endpoint warming is wrong target | Dropped; warm only `routes_v4/v6` next-hops + `fabrics` peer IPs |
| Codex r1 #3 / SMR r1 #4 / AGY r1 #6 (counter) | HA failover interaction with VRRP GARP burst | AGY's analysis adopted: warm pass and GARP both originate from same MAC/port, no upstream FIB confusion. §8 now states warm pass MUST run on RG-promote (not just safe) to repopulate FAILED entries from before promote |
| Codex r1 #4 (persistent worker) / AGY r1 #1 (rate-limit) | Per-key debounce + persistent state | §6 adds `NeighborManager::last_probed_at: FastMap<(i32, IpAddr), u64>` |
| SMR r1 #2 | Acceptance gate derivation missing | §9 now contains per-option latency derivation |
| AGY r1 #7 | No CI latency-bound test | §10 adds mocked netlink fixture test |
| Codex r1 #8 | CLI knob path not verified | §7 deferred — CLI surface bikeshed not blocking |

## 1. Issue framing

Cold iperf3 connect (post `ip neigh flush all` on the test host) takes
**3.371 s** wall-clock against the loss userspace cluster target
`172.16.80.200`. The published target in `docs/userspace-jit-design.md`
Phase 1 is "~2 ms cold connect". The real cost is ~1700× the documented
value.

Two compounding userspace defects sit at the heart of it:

- `PROBE_SCHEDULE_NS = [10, 60, 260] ms` in
  `userspace-dp/src/afxdp/neighbor_dispatch.rs:33-37`. After the third
  probe at 260 ms, **userspace fires no further ARP/NDP probes** for
  the lifetime of the queued packet. Per kernel-source review
  (`net/core/neighbour.c::__neigh_event_send` around line 1199-1275),
  the extra probes within one `retrans_time` window would only have
  queued the SKB anyway — but extending the schedule beyond `retrans_time`
  boundaries is what would generate fresh wire-level solicits.
- `PENDING_NEIGH_TIMEOUT_NS = 2_000_000_000` in
  `userspace-dp/src/afxdp/mod.rs:298`. At 2 s the original SYN frame is
  **dropped and recycled**; this lands ~1 s before the *second* TCP RTO
  retransmit at ~3 s would have arrived against a now-warm neighbor.

Once the original SYN is dropped, the only path back is the client TCP
RTO retransmit chain (~1 s, then ~3 s cumulative). Kernel ARP eventually
resolves on its own at the 1 s `retrans_time_ms` cadence and the second
retransmit succeeds — hence the observed 3.371 s.

## 2. Honest scope/value framing

The user-visible cost is *every cold connect to a destination whose
neighbor entry has aged out / failed*. Concretely:

- After daemon restart / reboot, every distinct egress next-hop costs
  multiple seconds for the first flow.
- After `ip neigh flush` (lab) or NUD GC reaching `NUD_FAILED` (prod).
  STALE entries do work (kernel queues new packets while soliciting).
- Operator-visible symptom: "the first iperf3 / curl / SSH takes 3-4 s
  but subsequent connects are instant".

The aggregate throughput gain is **zero** — established flows are
unaffected. The win is bounded to first-packet latency in steady-state,
plus a meaningful improvement to restart/failover impressions.

If reviewers conclude the perf gain is too small to justify the churn,
**PLAN-KILL is an acceptable verdict**. The 16× acceptance gate
(3.371 s → 200 ms) requires the proactive warming because B alone
cannot guarantee a sub-200ms cold connect on zero-copy AF_XDP where
the initial probe can be lost in the XSK-owned TX queue.

## 3. Empirical baseline

From `gh issue view 1636`:

```
1779989028.354036667
Connecting to host 172.16.80.200, port 5201
[  5] local 10.0.61.102 port 54416 connected to 172.16.80.200 port 5201
1779989031.725052712
```

**Cold connect: 3.371 s**

Reconstructed timeline (issue body, validated against code review):

| t (ms) | event |
|---|---|
| 0 | SYN arrives, `MissingNeighbor`, queued in `pending_neigh`, initial probe via `trigger_kernel_arp_probe()` |
| 10 | userspace probe slot 0 fires (or dedup-skips); inside `retrans_time` window so kernel queues but no fresh wire solicit |
| 60 | userspace probe slot 1 (same: queue only) |
| 260 | userspace probe slot 2 — **last** userspace-fired probe |
| 260-1000 | nothing on the wire from userspace; kernel ARP timer at `retrans_time_ms = 1000` not yet expired |
| ~1000 | kernel solicit retransmit fires (kernel's own scheduler) |
| 1000 (client) | TCP RTO #1 expires; client sends SYN retransmit; userspace already has the queued SYN, neighbor still INCOMPLETE |
| 2000 | `PENDING_NEIGH_TIMEOUT_NS` expires → **original queued SYN dropped**, frame recycled to fill ring |
| ~3000 (client) | TCP RTO #2 expires; second SYN retransmit; kernel has resolved by now; SYN forwards on fast path |
| 3371 | iperf3 sees `connected` |

## 4. What's already shipped / partially relevant

- `trigger_kernel_arp_probe()` (`userspace-dp/src/afxdp/neighbor.rs:36`):
  SOCK_RAW ICMP echo with `SO_BINDTODEVICE`. Sending an ICMP echo to an
  unresolved next-hop kicks the kernel's own ARP/NDP machinery; the
  reply hits `neigh_monitor_thread()` via NETLINK_ROUTE RTMGRP_NEIGH
  multicast and lands in `dynamic_neighbors` within microseconds of
  kernel resolution.
- `neigh_monitor_thread()` (`neighbor.rs:374`): subscribed to
  `RTMGRP_NEIGH`, runs `parse_neighbor_msg()` on `RTM_NEWNEIGH` (28) /
  `RTM_DELNEIGH` (29). Bumps `neighbor_generation`.
- `retry_pending_neigh()` (`neighbor_dispatch.rs:47`): runs on every
  poll cycle (both the work path AND the idle-RX path — see
  `worker/lifecycle.rs:135` and `:296`). **Per-packet timestamp**:
  the timeout check is `now_ns.saturating_sub(pkt.queued_ns) >
  PENDING_NEIGH_TIMEOUT_NS` (`neighbor_dispatch.rs:100`); each pkt has
  its own `queued_ns`. New SYNs get a fresh window.
- Dedup per `(egress_ifindex, next_hop)` per sweep so N pending packets
  behind one unresolved neighbor coalesce to one probe per slot.
- `PendingNeighPacket` carries `probe_attempts: u8` so each schedule
  slot fires at most once per packet.
- `MAX_PENDING_NEIGH = 4096` (was 64 before #946) gives plenty of
  headroom for cold-start bursts; the issue is *time*, not *capacity*.

## 5. Kernel-side ARP timing (confirmed by Codex + AGY against Linux source)

This section is the central architectural insight that drives the
recommendation. Quoting Codex r1 finding #1:

> In `net/core/neighbour.c:1199-1275`, `__neigh_event_send()` only sets
> `immediate_probe` when transitioning into `NUD_INCOMPLETE`; if the
> entry is already `NUD_INCOMPLETE`, it queues the skb and returns.
> `neigh_timer_handler()` then schedules further probes using
> `RETRANS_TIME` at `net/core/neighbour.c:1156-1161`. So repeated
> userspace `sendto()` calls do not force fresh ARPs inside
> `retrans_time`.

Implication: **option A is heartbeat-only** within a `retrans_time`
window. With kernel `retrans_time_ms = 1000` (default), adding userspace
probes at t=500, 1000, 1500 ms produces *one* extra wire-side solicit
(the one that crosses the 1000ms boundary). With kernel `retrans_time_ms
= 250` (option B), adding userspace probes adds zero wire-side value
because the kernel's own retrans timer already fires at every 250ms.

**Conclusion: option A is removed from the recommended set.** Kernel
retrans (B) is the dominant lever for unknown next-hops; proactive
warming (C) is the dominant lever for known next-hops.

## 5.1 Kernel solicit defaults (per Codex r2 #6 + SMR r2 #10)

Linux kernel defaults (from `Documentation/networking/ip-sysctl.rst` and
`net/core/neighbour.c::neigh_table` defaults arrays):

| sysctl | Default | Meaning |
|--------|---------|---------|
| `ucast_solicit` | 3 | unicast probes when refreshing a STALE/PROBE entry |
| `mcast_solicit` | 3 | multicast solicits to resolve an INCOMPLETE entry |
| `app_solicit` | 0 | userspace-app probes (off by default) |
| `delay_first_probe_time` | 5 | seconds before first PROBE state solicit |
| `retrans_time_ms` | 1000 | ms between retransmits |
| `gc_stale_time` | 60 | seconds before entry transitions to STALE |
| `base_reachable_time_ms` | 30000 | ms a confirmed entry stays REACHABLE |

For cold UNKNOWN next-hops, the path is `mcast_solicit` (3 attempts) at
`retrans_time_ms` intervals. With B=250ms: cold-fail window is roughly
`3 × 250ms = 750ms` before the kernel marks `NUD_FAILED`. With default
1000ms: roughly `3 × 1000ms = 3000ms` (which matches today's observed
3.371s behavior).

This directly informs:
- **D timing choice (revised per AGY r3 #4)**: The kernel neighbor
  state machine is async and unaware of userspace queue state. The
  kernel transitions to NUD_FAILED at ~750ms regardless of when
  userspace drops the packet. Two timing choices:
  - **D=700ms**: drop before kernel gives up. Loses 50ms window
    (700-750ms) where late resolution could have delivered the
    queued SYN #1. SYN #2 at t=1000ms encounters NUD_FAILED →
    fresh probe → resolve → forward.
  - **D=800ms**: drop after kernel marks FAILED. Preserves the
    50ms window where late kernel resolution between 700-750ms
    could have flushed the queue successfully. SYN #2 at t=1000ms
    encounters NUD_FAILED (same as 700ms case) → fresh probe →
    resolve → forward.
  - The 800ms case is strictly **>= 700ms case** in expected
    outcome (it preserves an extra 50ms window of opportunity to
    deliver SYN #1 without affecting the SYN #2 path).
  - **Recommendation**: D = **800ms**.
- **Snapshot warm-pass interaction**: when the warmer worker fires a
  probe, the kernel runs its own 3-attempt × `retrans_time_ms` schedule.
  Userspace need not retry — kernel handles. (Per AGY r2 #4 framing.)
- **NUD_FAILED handling**: when netlink reports `RTM_NEWNEIGH` with
  state `NUD_FAILED`, the existing `parse_neighbor_msg()` path removes
  the entry from `dynamic_neighbors`. The next MissingNeighbor will
  re-fire the probe sequence — but this is an edge case the plan
  should acknowledge rather than depend on.

## 6. Multiple path options (the design space)

| ID | Mechanism | Where it edits | Cold-connect floor | Failure-cost | HA-failover risk | Reversibility |
|----|-----------|----------------|--------------------|--------------|------------------|---------------|
| ~~A~~ | ~~Extend userspace `PROBE_SCHEDULE_NS`~~ | ~~`neighbor_dispatch.rs:33`~~ | Heartbeat-only; no wire-side win inside `retrans_time` | n/a | n/a | **REMOVED — not the lever** |
| **B** | Lower kernel `net.ipv4.neigh.default.retrans_time_ms` (and v6) via sysctl drop-in from 1000 → 250 ms | systemd sysctl-drop-in shipped with the deploy; no Rust code | Floor: ~250-500 ms typical; ~500 ms worst case (one missed solicit). Does NOT guarantee 200 ms gate on zero-copy XSK-owned TX where initial probe can be lost | none | none — kernel-wide setting, identical on both nodes | sysctl revert |
| **C** | Proactive neighbor warm at config-apply: for `routes_v4/v6` next-hops + `fabrics.peer_addr`, fire `trigger_kernel_arp_probe()` once per (ifindex, hop) with 5s rate-limit per key | `coordinator/mod.rs::refresh_runtime_snapshot()` tail + new `NeighborManager::last_probed_at` map | Cold connect to a *known* next-hop: ~1-10 ms (neighbor pre-resolved before first user flow) | falls through to today's path | LOW (per AGY r1 #6: warm pass and GARP share MAC/port; no upstream confusion). MUST run on RG-promote to repopulate post-promote FAILED entries | per-config knob revert |
| **D** | Lower `PENDING_NEIGH_TIMEOUT_NS` from 2000 to 800 ms | `mod.rs:298` (one-line constant) | Floor: ~1020 ms worst-case (per AGY r1 #2 derivation). Per-packet timestamp means TCP retransmit SYN #2 gets fresh 800ms window and is forwarded once kernel resolves | minor — extra client RTO #1 cost is unavoidable but cold connect drops from 3.371 s to ~1.02 s | none | constant revert |
| **B + C** | both | both | ≤200 ms gate met for known next-hops via C; ~250-500 ms typical for unknown via B | sum of B and C | as C | as B + as C |
| **B + D** | both | both | ~1.02 s worst case; ~50 ms typical for known next-hops if kernel resolution is fast | both | none | both |
| **B + C + D** | all | both | ≤200 ms for known; ~1.02 s for unknown after RTO #1; defence-in-depth | sum | as C | per-knob revert |

## 7. Concrete design — recommended: B as PR-1, then C as PR-2, then evaluate D

Per Codex r1 #5: **ship B first as a sysctl-only PR**. Measure cold
connect on the loss userspace cluster against an unknown next-hop. If
B alone gets us to ≤200 ms (skeptical — AGY r1 #4 explains why zero-copy
XSK first-probe loss makes this unreliable), C may be deferred. If not
(expected), C ships as PR-2.

### B (PR-1): kernel retrans_time_ms sysctl drop-in

Ship a sysctl drop-in file (e.g., `/etc/sysctl.d/99-xpf-neighbor.conf`)
via the deploy that sets:

```
net.ipv4.neigh.default.retrans_time_ms = 250
net.ipv6.neigh.default.retrans_time_ms = 250
```

Applied at xpfd start via `systemctl reload-or-restart systemd-sysctl`
(or implicit via package install). No Rust code touched.

Verify on the loss userspace cluster:

```
sysctl net.ipv4.neigh.default.retrans_time_ms
sysctl net.ipv6.neigh.default.retrans_time_ms
ip ntable get default
```

Measure cold connect 10× post-flush; if median ≤200 ms across 10 runs,
the gate is empirically met without C. If not (expected), proceed to C.

**Test plan for PR-1**: cold-connect measurement harness from the
issue body diagnostic section, 10 runs, median + p99 reported.

### C (PR-2): proactive neighbor warm at config-apply

Site: tail of `Coordinator::refresh_runtime_snapshot()` in
`userspace-dp/src/afxdp/coordinator/mod.rs:435+`. After the new
`ForwardingState` has been published into `ha.forwarding`, walk the
forwarding state and fire one warm probe per `(egress_ifindex,
next_hop)` whose neighbor is **not** already resolved AND **not**
recently probed.

**Architectural framing** (per AGY r2 #4): the warmer worker fires
exactly ONE probe per `(ifindex, hop, generation)` tuple. Once fired,
the kernel runs its own 3-attempt × `retrans_time_ms` schedule and
netlink reports the result. The warmer worker does NOT retry on its own;
re-warming for a key only happens when (a) the 5s `last_probed_at`
window has elapsed AND (b) a new snapshot generation has triggered a
fresh `queue_warm_pass()` call AND (c) the neighbor is still
unresolved. This minimizes wire-side ARP/NDP solicits and avoids any
risk of solicit storms.

**Required infrastructure** (from AGY r1 #1 / Codex r1 #4):

Add a `last_probed_at: Arc<Mutex<FastMap<(i32, IpAddr), u64>>>` field
on `NeighborManager` (`coordinator/neighbor_manager.rs`). Before each
`trigger_kernel_arp_probe()` call, check elapsed since last probe of
the same key; skip if < 5 s. This bounds:
- Concurrent FD allocation under config storm
- Wire-side solicit storms for permanently-unreachable next-hops
- CPU cost of repeated socket()+sendto()+close() on the same target

**Snapshot-level rate-limit**: store the last full warm sweep timestamp
on the coordinator; skip the entire sweep if < 1 s elapsed. Coalesces
config-storm snapshot apply down to 1 sweep/s max.

**Targets to warm** (per AGY r1 #3 + SMR r1 #5 — dropped tunnel_endpoints):

1. `forwarding.routes_v4.values().flat_map(|rs| rs.iter()).filter_map(|r| r.next_hop)` — static + BGP/OSPF/IS-IS routes (FRR has already populated these into the snapshot)
2. Same for `routes_v6`
3. `forwarding.fabrics.iter().map(|f| f.peer_addr)` — fabric peers
4. **NOT** tunnel_endpoints — kernel handles encap underlay and most
   tunnel destinations are multi-hop. Underlay next-hops are in
   `routes_v4/v6` if relevant.

**Threading model**: do NOT spawn a thread per snapshot (per AGY r1 #1
risk). Instead, attach a single long-lived "neighbor warmer" worker
thread spawned at coordinator init, fed via an MPSC queue. The
coordinator's `refresh_runtime_snapshot()` tail enqueues
`(ifindex, hop)` keys; the warmer worker pulls from the queue,
deduplicates against `last_probed_at`, and fires the probe. This:
- Bounds thread count to 1
- Bounds FD allocation to whatever the warmer is doing at one time
- Backpressures naturally if the worker can't keep up

Implementation sketch:

```rust
// in NeighborManager
pub(crate) struct NeighborManager {
    pub(crate) dynamic: Arc<ShardedNeighborMap>,
    pub(crate) generation: Arc<AtomicU64>,
    pub(crate) manager_keys: Arc<Mutex<FastSet<(i32, IpAddr)>>>,
    pub(crate) monitor_stop: Option<Arc<AtomicBool>>,
    // new (r2 round folded in):
    pub(crate) last_probed_at: Arc<Mutex<FastMap<(i32, IpAddr), u64>>>,
    pub(crate) warm_queue: Option<crossbeam_channel::Sender<WarmItem>>,
    pub(crate) warm_stop: Option<Arc<AtomicBool>>,
    pub(crate) warm_generation: Arc<AtomicU64>,
    pub(crate) warm_drops: Arc<AtomicU64>, // channel-full telemetry
}

#[derive(Clone)]
pub(crate) struct WarmItem {
    ifindex: i32,
    hop: IpAddr,
    iface_name: String,
    generation: u64, // queued under this snapshot gen
    rg_id: i32,      // owning routing group (per AGY r5 #1: HA is per-RG, not global)
}

// in Coordinator::refresh_runtime_snapshot tail:
self.queue_warm_pass(); // non-blocking enqueue

fn queue_warm_pass(&mut self) {
    // Per-RG active gate is checked PER-KEY below (the global is_active()
    // shorthand from v4-v5 was a placeholder; the real xpf architecture
    // is per-RG via HAGroupRuntime::is_forwarding_active(now_secs) — per
    // AGY r5 #1). We still rate-limit at sweep level here, then dispatch
    // per-RG via the rg_id field on WarmItem.
    //
    // snapshot-level rate-limit (returns BEFORE generation bump per Codex r4 #2).
    let now = monotonic_nanos();
    if now.saturating_sub(self.last_warm_sweep_ns) < 1_000_000_000 {
        return;
    }
    self.last_warm_sweep_ns = now;

    // Generation bump: only on ADMITTED sweeps (Codex r4 #2). Any
    // in-flight queue items from previous snapshot are now stale and
    // will be dropped on dequeue.
    let gen = self.neighbors.warm_generation.fetch_add(1, Ordering::Release) + 1;

    let snapshot = &self.forwarding;
    let mut seen: FastSet<(i32, IpAddr)> = FastSet::default();
    let already_resolved = |key: &(i32, IpAddr)| -> bool {
        snapshot.neighbors.contains_key(key)
            || self.neighbors.dynamic.contains_key(key)
    };

    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut enqueue = |egress_ifindex: i32, hop: IpAddr| {
        if egress_ifindex <= 0 { return; }
        if hop.is_unspecified() || hop.is_loopback() || hop.is_multicast() { return; }
        let key = (egress_ifindex, hop);
        if !seen.insert(key) { return; }
        if already_resolved(&key) { return; }
        // Per-RG HA check (AGY r5 #1): resolve egress to its owning RG;
        // only enqueue if that RG is currently ACTIVE on this node.
        let rg_id = owner_rg_for_flow(snapshot, egress_ifindex);
        let rg_active = self.ha.rg_runtime.load()
            .get(&rg_id)
            .map(|g| g.is_forwarding_active(now_secs))
            .unwrap_or(false);
        if !rg_active { return; }
        if let Some(name) = snapshot.ifindex_to_name.get(&egress_ifindex) {
            if let Some(tx) = &self.neighbors.warm_queue {
                let item = WarmItem {
                    ifindex: egress_ifindex, hop,
                    iface_name: name.clone(), generation: gen, rg_id,
                };
                if tx.try_send(item).is_err() {
                    // Bounded-channel full or worker disconnected: log + telemetry.
                    self.neighbors.warm_drops.fetch_add(1, Ordering::Relaxed);
                    if cfg!(feature = "debug-log") {
                        eprintln!("xpf-userspace-dp: warm queue full or worker died; key={:?}", key);
                    }
                }
            }
        }
    };

    // iterate routes_v4 + routes_v6 + fabrics (NOT tunnel_endpoints — per AGY r1 #3)
}

// in the warmer worker (long-lived, single thread):
//
// IPv6 NDP: trigger_kernel_arp_probe in userspace-dp/src/afxdp/neighbor.rs:36
// dispatches on IpAddr variant — AF_INET → SOCK_RAW ICMP echo; AF_INET6 →
// SOCK_RAW ICMPv6 echo. The same function handles both protocols; no separate
// trigger_ndp_probe needed. (Confirmed dual-stack per Codex r4 #5.)
fn warmer_loop(rx: Receiver<WarmItem>,
               last_probed: Arc<Mutex<FastMap<(i32, IpAddr), u64>>>,
               warm_generation: Arc<AtomicU64>,
               ha: Arc<HaSnapshot>, // reference to HA active flag
               stop: Arc<AtomicBool>) {
    let mut last_gc_ns = monotonic_nanos();
    while !stop.load(Ordering::Relaxed) {
        // Run GC at the top of EVERY iteration (idle + dequeue path).
        // Per AGY r3 #2: GC keyed off a Timeout-only path is bypassed
        // under continuous load.
        let now = monotonic_nanos();
        if now.saturating_sub(last_gc_ns) >= 60_000_000_000 {
            if let Ok(mut map) = last_probed.lock() {
                map.retain(|_k, &mut t| now.saturating_sub(t) < 300_000_000_000);
            }
            last_gc_ns = now;
        }
        let item = match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(it) => it,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                // Coordinator gone — clean exit.
                eprintln!("xpf-userspace-dp: neighbor warmer worker: channel disconnected; exiting");
                return;
            }
        };
        // Re-check active state + generation IMMEDIATELY before firing
        // (per Codex r4 #1 + AGY r4 #1 + AGY r5 #1). Without this, an
        // item queued under the active generation but dequeued after
        // demotion would still fire trigger_kernel_arp_probe(); §9
        // invariant 2 stated but not mechanically guaranteed otherwise.
        // Per-RG check via item.rg_id (AGY r5 #1).
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let rg_active = ha.rg_runtime.load()
            .get(&item.rg_id)
            .map(|g| g.is_forwarding_active(now_secs))
            .unwrap_or(false);
        if !rg_active {
            continue;
        }
        // Generation collapse: drop stale items (Codex r2 #3).
        if item.generation != warm_generation.load(Ordering::Acquire) {
            continue;
        }
        let key = (item.ifindex, item.hop);
        let now = monotonic_nanos();
        // expect() on lock poison (AGY r4 #1): if a coordinator-side
        // panic poisoned the mutex, silently skipping forever would
        // leave warming "alive but disabled" — invisible. Panic-on-poison
        // kills the worker, breaking the MPSC channel; the next try_send
        // hits TrySendError::Disconnected, increments warm_disconnected,
        // and emits the operator-visible warning.
        let skip = {
            let mut map = last_probed.lock().expect("last_probed mutex poisoned — neighbor warming forcibly disabled");
            match map.get(&key) {
                Some(t) if now.saturating_sub(*t) < 5_000_000_000 => true,
                _ => {
                    map.insert(key, now);
                    false
                }
            }
        };
        if !skip {
            trigger_kernel_arp_probe(&item.iface_name, item.hop);
            // Per AGY r2 #4: fire ONE probe; kernel handles its own
            // 3-attempt × retrans_time schedule.
        }
    }
}
```

**Producer-side error handling** (per AGY r3 #1): the `try_send` failure
mode must distinguish between channel-Full (queue saturation) and
channel-Disconnected (worker thread died — fatal). The producer:

```rust
match tx.try_send(item) {
    Ok(()) => {}
    Err(crossbeam_channel::TrySendError::Full(_)) => {
        self.neighbors.warm_drops.fetch_add(1, Ordering::Relaxed);
        if cfg!(feature = "debug-log") {
            eprintln!("xpf-userspace-dp: warm queue full (cap=4096); dropping {:?}", key);
        }
    }
    Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
        self.neighbors.warm_disconnected.fetch_add(1, Ordering::Relaxed);
        // Once-only transition log (AGY r4 #3 + Codex r4 #3): under
        // route churn this can fire 100× per snapshot otherwise.
        if !self.neighbors.warned_disconnect.swap(true, Ordering::Relaxed) {
            // Not debug-gated — operators must see ONCE.
            eprintln!(
                "xpf-userspace-dp: ERROR: neighbor warmer worker disconnected; \
                 proactive neighbor warming is DISABLED until restart"
            );
        }
    }
}
```

`warned_disconnect` is an `AtomicBool` on `NeighborManager`. `swap(true)`
returns the prior value; the inner `eprintln` runs only on the first
transition from false→true. Prometheus surface (`warm_disconnected`
counter) still reflects per-key totals.

Both `warm_drops` and `warm_disconnected` exposed as Prometheus
counters via the existing dataplane metrics endpoint. Mandatory not
optional — Prometheus surface is the only operator-visible signal in
production builds (where `debug-log` is off).

**Channel sizing**: bounded `crossbeam_channel::bounded(4096)`. Plan
accommodates 4096 items in flight which exceeds typical FRR snapshot
route counts (handful to dozens). On overflow, the new item is dropped
and `warm_drops` is incremented; debug log fires (when
`feature=debug-log`).

**RG-promote cache clear** (AGY r2 #2): on cluster state transition to
ACTIVE/PRIMARY, clear `last_probed_at` to avoid 5s lockout of probes
that failed during the transient down state.

**Link-UP cache clear** (AGY r3 #3): when an interface transitions
DOWN→UP, clear all `last_probed_at` entries whose `ifindex` matches
the now-UP interface. This catches the post-promote link negotiation
window (LACP / STP / VLAN negotiation 1-2 sec). Wired through the
existing netlink RTM_NEWLINK monitor:

```rust
// Coordinator gets methods called from the cluster + link state paths:
pub(super) fn on_rg_promote_active(&self) {
    if let Ok(mut map) = self.neighbors.last_probed_at.lock() {
        map.clear();
    }
}

pub(super) fn on_link_up(&self, ifindex: i32) {
    if let Ok(mut map) = self.neighbors.last_probed_at.lock() {
        map.retain(|&(ifx, _), _| ifx != ifindex);
    }
}
```

Operator surface: defer the `set chassis dataplane proactive-neighbor-warm`
knob to a follow-up. Default-on, no opt-out, ship as a behavior change.
If operator pushback emerges, add the knob.

### D (PR-3, optional): lower PENDING_NEIGH_TIMEOUT_NS

If B + C does not fully cover edge cases (e.g., the first SYN to a
truly-unknown next-hop where C couldn't warm), D drops the worst-case
from 3.371 s to ~1.02 s. The per-packet timestamp guarantees new SYNs
get a fresh window (per AGY r1 #2 trace).

PR-3 is a one-line constant change with a test update. Trivial to ship
or defer. Recommend shipping after measuring B + C on the test cluster.

## 8. Public API preservation

- `Coordinator::refresh_runtime_snapshot()` keeps its existing signature
- `trigger_kernel_arp_probe()` unchanged
- `NeighborManager` gains 3 new fields (`last_probed_at`, `warm_queue`,
  `warm_stop`); all `pub(crate)` — no out-of-crate surface
- `Coordinator` gains `last_warm_sweep_ns: u64` field
- New function: `Coordinator::queue_warm_pass()` — `pub(super)`,
  callable only from the coordinator
- Operator-visible CLI: deferred (no new knob in initial ship)

No protocol changes. No `ConfigSnapshot` schema changes.

## 9. Hidden invariants the change must preserve

1. **No blocking call on the coordinator hot path**. `queue_warm_pass()`
   uses non-blocking MPSC enqueue (`try_send`); coordinator returns
   promptly.
2. **HA failover ordering** (per Codex r2 #4 + AGY r1 #6 + AGY r2 #2
   + Codex r4 #1 + AGY r4 #1 + AGY r5 #1):
   xpf HA is **per Routing Group (RG)**, NOT a global active flag.
   Each WarmItem carries `rg_id`. The active check at both queue and
   pre-fire uses `HAGroupRuntime::is_forwarding_active(now_secs)` for
   the item's specific RG.
   - Queue side: `queue_warm_pass()` resolves egress to its RG via
     `owner_rg_for_flow(snapshot, egress_ifindex)` and only enqueues
     when that RG's `HAGroupRuntime::is_forwarding_active(now_secs)`
     is `true`. Standby RGs are silently skipped per key.
   - Worker side: warmer re-checks the same `HAGroupRuntime::is_forwarding_active`
     for `item.rg_id` IMMEDIATELY before calling
     `trigger_kernel_arp_probe()`. Without this, an item queued under
     an active RG but dequeued after demotion would still fire.
   - Interface / MAC / VIP / egress maps are programmed before the RG
     is marked active in `HAGroupRuntime` (existing xpf invariant), so
     the per-RG active check implies the dataplane prerequisites are in
     place.
   - On RG-promote, `last_probed_at.clear()` is called via
     `Coordinator::on_rg_promote_active()` to avoid 5s lockout of
     probes that failed during transient down state.
3. **Don't probe interfaces in transient down state**. Use
   `ifindex_to_name` lookup; if missing from snapshot, skip silently.
4. **Don't loop-warm**. `last_probed_at` 5s rate-limit per key;
   snapshot-level 1s rate-limit for the whole sweep.
5. **Don't warm broadcast / multicast / loopback / unspecified
   addresses**. Filter before enqueue.
6. **`PENDING_NEIGH_TIMEOUT_NS` change (PR-3)**: if shipped, lower to
   **800 ms** (per AGY r3 #4 — kernel state machine is async; 800ms
   preserves the late-resolution window 700-750ms without affecting
   the SYN #2 path). Update the test
   `schedule_total_window_under_pending_neigh_timeout` in
   `neighbor_dispatch.rs:557-567` accordingly.
7. **Generation collapse**: `warm_generation` is bumped on each
   `queue_warm_pass()`; in-flight items from previous generations are
   dropped on dequeue by the warmer worker.
8. **Single-shot probe per (key, generation)**: the warmer worker fires
   exactly ONE `trigger_kernel_arp_probe()` per key per generation; the
   kernel runs its own 3-attempt × `retrans_time_ms` schedule. No
   userspace retry loop.
9. **Bounded queue + telemetry**: bounded `crossbeam_channel::bounded(4096)`;
   distinguish `TrySendError::Full` (counted as `warm_drops`, log gated
   on `debug-log`) from `TrySendError::Disconnected` (counted as
   `warm_disconnected`, log NOT gated — operators must see). Both
   counters MANDATORILY exposed as Prometheus metrics.
10. **`last_probed_at` cleared on link-UP for that ifindex** (AGY r3 #3):
    avoids the transient-down lockout window where probes fired during
    link negotiation get rate-limited for 5s.
11. **GC pruning runs every iteration of the warmer loop** (idle OR
    dequeue), keyed off `last_gc_ns` (AGY r3 #2). Under continuous load
    where Timeout is never hit, the GC still runs on each dequeue.

## 10. Acceptance gate derivation (qualified per Codex r2 #5 + SMR r2 #2)

Assumptions used in each row:
- "first probe succeeds" = SYN's initial `trigger_kernel_arp_probe()`
  reaches the wire and elicits a reply
- "initial-resolution-train failed" = the SYN-triggered probe is dropped (e.g., XSK-owned
  TX queue contention on mlx5 zero-copy bind window per AGY r1 #4)
- "known next-hop" = the next-hop appears in `routes_v4/v6` or `fabrics`
  at the time of the most recent `queue_warm_pass()` AND that warm pass
  has completed (warmer worker drained the in-flight item AND netlink
  has delivered the resolution into `dynamic_neighbors`)
- "concurrent-with-warm" = SYN arrives while warm pass is still in
  flight; behavior = same as today's MissingNeighbor cold path

| Option | Median typical case | p99 worst case | Gate met? |
|--------|---------------------|----------------|-----------|
| Today (master) | 3.371 s | 3.371 s | NO |
| A only | 3.371 s | 3.371 s | NO (kernel rate-limit) |
| B only — first probe succeeds | ~50 ms | ~250-300 ms (one missed solicit + retrans + netlink + retry sweep) | TYPICAL: marginal, p99: NO |
| B only — initial-resolution-train failed | ~750 ms (3 × 250ms before NUD_FAILED) | up to PENDING_NEIGH_TIMEOUT_NS = 2 s (then ~1 s extra for TCP RTO #2) | NO |
| C only (post-warm-complete, kernel retrans 1000ms default) | ~1-10 ms (neighbor pre-resolved into `dynamic_neighbors`) | varies | KNOWN+post-warm: YES, concurrent-with-warm: NO |
| B + C — post-warm-complete | ~1-10 ms | ~50 ms (netlink propagation tail) | YES |
| B + C — concurrent-with-warm or unknown | ~50 ms typical (B path with first-probe-succeeds) | ~500-1000 ms (initial-resolution-train failed + kernel gives up at 750ms + 2s PENDING_NEIGH_TIMEOUT) | TYPICAL: yes, p99: NO |
| B + C + D (PENDING_NEIGH_TIMEOUT_NS=700ms) — concurrent-with-warm or unknown — first probe succeeds | ~50 ms | ~250-300 ms | YES |
| B + C + D — initial-resolution-train failed | ~700 ms (dropped while kernel still INCOMPLETE), then SYN #2 at t=1000ms triggers fresh probe sequence, neighbor resolves by t=~1050ms (kernel has cached partial state) | ~1.02 s (matches AGY r1 #2 derivation) | NO for p99, but 3.3× better than today |
| B + C + D + NUD_FAILED kicker | as above + dataplane re-fires probe on netlink RTM_NEWNEIGH state=NUD_FAILED (out of scope for initial ship) | ~1.0 s | borderline |

Conclusion:
- **For known next-hops (the common operator case)**, B + C with the
  warm pass having completed gets us to **~1-10 ms** — well under the
  200 ms gate.
- **For unknown next-hops**, the gate is met on the typical first-probe-
  succeeds case (~50 ms) but NOT on the first-probe-LOST p99 case.
  With B + C + D, the absolute worst-case is bounded to ~1.02 s — a
  **3.3× improvement over today**.

Gate language updated to: "≤200 ms cold connect for operator-configured
next-hops with warm pass complete; ≤500 ms typical for unknown
next-hops; ≤1.02 s worst case under initial-resolution-train-failed
path (with D shipped). **Sustained packet loss is NOT bounded by D**:
if both the initial and SYN #2 resolution trains fail, the cold connect
falls back to TCP RTO #3 cliff at t=7s — D narrows the typical worst-
case but does not eliminate pathological loss scenarios."

## 11. Risk assessment

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | Warm pass is additive; failure mode is same as today |
| Lifetime / borrow | LOW | New helper takes `&mut self` on coordinator; long-lived warmer worker spawned at init |
| Performance regression | LOW (control plane) / NONE (data plane) | One worker thread idle when nothing to warm; bounded FD use |
| Architectural mismatch (#946/#961 dead-end pattern) | LOW | Mechanism is mechanically simple — fire existing function from one new place |
| HA failover impact | LOW (per AGY r1 #6) | Warm pass + GARP share MAC/port; no upstream FIB confusion. Warm pass on RG-promote is REQUIRED (not just safe) to repopulate FAILED entries |
| Kernel ARP storm | LOW | Bounded by `last_probed_at` 5s key-level + 1s snapshot-level rate-limit |
| Acceptance gate met | MEDIUM-HIGH for known | C delivers; B fallback for unknown |
| FD exhaustion under config storm | LOW (mitigated) | Long-lived warmer worker + rate-limit avoids per-snapshot socket bursts |
| PR sequencing risk | LOW | B alone (sysctl) is fully reversible; C after empirical measurement informs whether D is needed |

## 12. Test plan

### Per-PR

**PR-1 (B sysctl)**:
- Update systemd/deploy machinery to ship `/etc/sysctl.d/99-xpf-neighbor.conf`
- Verify on the loss userspace cluster: `sysctl net.ipv{4,6}.neigh.default.retrans_time_ms` returns 250
- Cold-connect measurement: 10 runs of the issue body diagnostic harness, report median + p99
- No Rust code; no cargo test delta

**PR-2 (C proactive warm)**:
- New unit tests in `coordinator/tests.rs`:
  - `queue_warm_pass_fires_for_unresolved_next_hop`
  - `queue_warm_pass_skips_already_resolved`
  - `queue_warm_pass_skips_invalid_addresses` (multicast, loopback, unspecified)
  - `queue_warm_pass_dedups_within_one_call`
  - `queue_warm_pass_respects_5s_per_key_rate_limit`
  - `queue_warm_pass_respects_1s_snapshot_rate_limit`
  - `warmer_worker_processes_queue_messages`
  - `warmer_worker_shuts_down_on_stop_signal`
- New mocked-netlink integration test in `neighbor_dispatch.rs` (per AGY r1 #7):
  `cold_connect_resolves_within_simulated_window` — injects an RTM_NEWNEIGH after a configurable delay and asserts `retry_pending_neigh()` flushes the queue within budget
- Empirical: cold-connect measurement 10× on the cluster, median + p99 ≤200 ms for a known next-hop
- HA: `make test-failover` baseline must still complete ≤60 ms

**PR-3 (D timeout — optional, after measuring B+C)**:
- Update `PENDING_NEIGH_TIMEOUT_NS` to 800ms ONLY if PR-1 sysctl is
  empirically applied at runtime. Per AGY r4 #2 operational hazard: if
  PR-1 sysctl fails to apply (restricted container, sysctl namespace
  permission errors, admin overrides), kernel `retrans_time_ms` stays
  at 1000ms default. Then dropping at 800ms BEFORE the kernel's first
  wire-side solicit at t=1000ms means SYN #2 at t=1000ms still hits
  INCOMPLETE → kernel queues → SYN #2 dropped at t=1800ms → resolution
  lands at t=3000ms (SYN #3). **Regresses baseline.**
- **Mitigation**: at daemon init, read `/proc/sys/net/ipv4/neigh/default/retrans_time_ms`
  (and v6). If > 250, fall back to PENDING_NEIGH_TIMEOUT_NS=2000ms
  (today's value). Emit operator-visible warning on fallback.
- Pseudocode (per Codex r5 #1 + AGY r5 #2-#3 — dual-stack + per-interface +
  fail-closed + cached-once):
  ```rust
  use std::sync::OnceLock;
  static PENDING_NEIGH_TIMEOUT_NS: OnceLock<u64> = OnceLock::new();

  fn init_pending_neigh_timeout_ns(dataplane_ifindexes: &[i32]) -> u64 {
      // Read effective per-interface retrans_time_ms for BOTH v4 and v6
      // across every dataplane interface. Fail closed (= use 2_000_000_000)
      // on ANY missing file, parse error, or value > 250.
      let mut max_retrans: u32 = 0;
      for ifx in dataplane_ifindexes {
          let iface_name = match resolve_ifindex_to_name(*ifx) {
              Some(n) => n,
              None => return fallback(),
          };
          for family in ["ipv4", "ipv6"] {
              let path = format!("/proc/sys/net/{}/neigh/{}/retrans_time_ms", family, iface_name);
              let v = match read_sysctl_u32(&path) {
                  Ok(v) => v,
                  Err(_) => return fallback(),
              };
              if v > 250 { return fallback(); }
              max_retrans = max_retrans.max(v);
          }
      }
      // Also check default in case interfaces are created later.
      for family in ["ipv4", "ipv6"] {
          let path = format!("/proc/sys/net/{}/neigh/default/retrans_time_ms", family);
          let v = match read_sysctl_u32(&path) {
              Ok(v) => v,
              Err(_) => return fallback(),
          };
          if v > 250 { return fallback(); }
          max_retrans = max_retrans.max(v);
      }
      // All checks passed; use 800ms timeout.
      800_000_000
  }

  fn fallback() -> u64 {
      eprintln!(
          "xpf-userspace-dp: WARNING: kernel retrans_time_ms not <= 250 \
           on all dataplane interfaces (v4 AND v6) — using \
           PENDING_NEIGH_TIMEOUT_NS=2000ms (PR-3 inactive). Apply PR-1 \
           sysctl drop-in to enable."
      );
      2_000_000_000
  }

  // Called once at daemon init:
  PENDING_NEIGH_TIMEOUT_NS.set(init_pending_neigh_timeout_ns(&ifxs))
      .expect("PENDING_NEIGH_TIMEOUT_NS already initialized");

  // Hot-path callsite (was: `> PENDING_NEIGH_TIMEOUT_NS`):
  if now_ns.saturating_sub(pkt.queued_ns) > *PENDING_NEIGH_TIMEOUT_NS.get().unwrap_or(&2_000_000_000) {
      // drop
  }
  ```
- This is a runtime guard — operator does not have to rebuild the binary
  to revert; the sysctl is the single point of truth.
- Update test `schedule_total_window_under_pending_neigh_timeout` to
  assert `last < min(PENDING_NEIGH_TIMEOUT_NS) - 100_000_000` (use min
  to handle both 800ms and 2000ms paths)
- Cold-connect measurement with neighbor-warming disabled (force the
  unknown-next-hop path) to verify ~1.02 s worst case under correct
  sysctl configuration AND verify NO regression under degraded sysctl
  configuration (B unapplied → fallback to 2000ms)

### Smoke matrix

Loss userspace cluster, all 3 PRs:
- v4 push (`iperf3 -c 172.16.80.200 -p 5201`)
- v4 reverse (`-R`)
- v6 push (`iperf3 -c 2001:559:8585:80::200 -p 5201`)
- v6 reverse
- Per-class CoS-on (5201-5206)
- Per-class CoS-off

No regression in established-flow throughput.

## 13. Out of scope (explicitly)

- Static neighbor entries via `set protocols nd …` — pre-existing path
- IPv6 ND-specific edge cases (DAD, RA-derived next-hops)
- The `forwarding.neighbors` static map itself
- Operator-tunable PROBE_SCHEDULE_NS itself
- Aggressive `PENDING_NEIGH_TIMEOUT_NS` reduction below 800 ms
- Cross-vendor NIC-specific timing
- BPF map-based neighbor table tuning
- The `set chassis dataplane proactive-neighbor-warm` CLI knob — defer
  to follow-up if operator pushback emerges

## 14. Open questions for adversarial review (round 2)

1. Should warm-pass keys ALSO include `forwarding.connected_v4/v6`
   subnets? E.g., directly-connected interfaces with /24 prefixes have
   neighbors that aren't routed-via — should we warm the gateway IPs
   under those prefixes? Currently they only appear if a static route
   exists. Maybe scan `ip neigh` at startup and re-warm any FAILED
   entry for an active interface.

2. The 5 s per-key rate-limit window in `last_probed_at` is a guess.
   Should it be tied to kernel `retrans_time_ms` (e.g., 4× retrans
   window)? Or to NUD `gc_interval`? Empirical tuning required.

3. Should `last_probed_at` cleanup happen periodically (otherwise it
   grows unbounded as neighbors come and go)? A monotonic-clock LRU
   trim at coordinator GC?

4. Is the long-lived warmer worker thread the right pattern, or should
   we re-use the existing `neigh_monitor_thread`? Co-locating warm
   probes with the monitor would simplify lifecycle but adds latency
   to the recv() loop. Worth a reviewer opinion.

5. PR sequencing: should we land B and C atomically in one PR (lower
   review overhead, harder to bisect) vs sequenced two PRs (Codex r1 #5
   recommendation)? Two PRs is the bias.

## 15. Recommendation

**Ship B + C as separate PRs.** Defer D to PR-3 contingent on empirical
measurement. Sequence:

1. PR-1: B (sysctl drop-in) — low-risk, fully reversible, immediate measurable change
2. Measure B alone on loss userspace cluster (10 cold connects, median + p99)
3. PR-2: C (proactive warm with rate-limited long-lived warmer worker)
4. Re-measure B + C; verify ≤200 ms for known next-hops
5. PR-3 (optional): D (lower PENDING_NEIGH_TIMEOUT_NS to 800 ms) only
   if B + C does not cover the unknown-next-hop p99 acceptably

## 16. Reviewer convergence path

This is `/research` not `/engineer`. Convergence target: 3 of 3
(Claude SMR + Codex + AGY) on PLAN-READY for the recommended option
set, OR convergent PLAN-KILL with rationale.

Copilot reviews at `/engineer 1636` time on the implementation PR, not
now.
