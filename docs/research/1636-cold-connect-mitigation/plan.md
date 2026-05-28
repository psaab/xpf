# #1636 cold-connect / neighbor-resolution gap — research plan

**Status**: DRAFT v1 — pending adversarial plan review
**Base SHA**: `dbfbf680cc82` (origin/master @ 2026-05-28)
**Branch**: `research/1636-cold-connect-mitigation`
**Scope**: research-only, no production source edits, no PR

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
  the lifetime of the queued packet. The packet just spins on
  `retry_pending_neigh()` checking `dynamic_neighbors`.
- `PENDING_NEIGH_TIMEOUT_NS = 2_000_000_000` in
  `userspace-dp/src/afxdp/mod.rs:298`. At 2 s the original SYN frame is
  **dropped and recycled**; this lands ~1 s before the *second* TCP RTO
  retransmit at ~3 s would have arrived against a now-warm neighbor.

Once the original SYN is dropped, the only path back is the client TCP
RTO retransmit chain (~1 s, then ~3 s cumulative); kernel ARP eventually
resolves on its own at the 1 s `retrans_time_ms` cadence and the second
retransmit succeeds — hence the observed 3.371 s.

## 2. Honest scope/value framing

The user-visible cost is *every cold connect to a destination whose
neighbor entry has aged out*. Concretely:

- After daemon restart / reboot, every distinct egress next-hop costs
  multiple seconds for the first flow.
- After `ip neigh flush` (lab) or NUD GC (production: `gc_stale_time`
  default 60 s + `delay_first_probe_time` 5 s; STALE entries do work,
  but FAILED entries trigger this path).
- Operator-visible symptom: "the first iperf3 / curl / SSH takes 3-4 s
  but subsequent connects are instant".

The aggregate throughput gain is **zero** — established flows are
unaffected. The win is bounded to first-packet latency in steady-state,
plus a meaningful improvement to restart/failover impressions.

If reviewers conclude the perf gain is too small to justify the churn,
**PLAN-KILL is an acceptable verdict**. The 16× acceptance gate
(3.371 s → 200 ms) does not require zero-allocation hot-path work or a
new data structure; the costs are mostly knob tuning + a one-shot
config-apply warm pass. Risk is concentrated in option C's HA-failover
behavior (an active node sending unsolicited solicits on RG-promote can
storm the kernel ARP table) and in option D's interaction with TCP RTO.

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
| 10 | userspace probe slot 0 fires (or dedup-skips if same `(egress, hop)` already this sweep) |
| 60 | userspace probe slot 1 |
| 260 | userspace probe slot 2 — **last** userspace-fired probe |
| 260-1000 | nothing on the wire from userspace; kernel ARP timer at `retrans_time_ms = 1000` not yet expired |
| ~1000 | kernel sends its own ARP retransmit if it still has packets queued or has a hold-down on the neigh entry |
| 1000 (client) | TCP RTO #1 expires; client sends SYN retransmit; userspace **already has the queued SYN, neighbor still INCOMPLETE** |
| 2000 | `PENDING_NEIGH_TIMEOUT_NS` expires → **original queued SYN dropped**, frame recycled to fill ring |
| ~3000 (client) | TCP RTO #2 expires; client sends second SYN retransmit; by now kernel has resolved (or our XDP demux delivered the ARP reply); SYN forwards on the fast path |
| 3371 | iperf3 sees `connected` |

Two compounding failures: (1) userspace stops probing at 260 ms; (2)
`PENDING_NEIGH_TIMEOUT_NS` drops the original SYN before TCP would have
naturally retransmitted into a warm neighbor.

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
  `worker/lifecycle.rs:135` and `:296`). Dedup per
  `(egress_ifindex, next_hop)` per sweep so N pending packets behind
  one unresolved neighbor coalesce to one probe per schedule slot.
- `PendingNeighPacket` (`types/mod.rs` near 96) carries
  `probe_attempts: u8` so each schedule slot fires at most once per
  packet.
- `MAX_PENDING_NEIGH = 4096` (was 64 before #946) gives plenty of
  headroom for cold-start bursts; the issue is *time*, not *capacity*.

The above already establishes the bones of a more-aggressive schedule —
adding more slots is mechanical. Critically, the kernel-side resolution
timing is the dominant clock; our extra probes only help if they
encourage the kernel to retry sooner.

## 5. Multiple path options (the design space)

| ID | Mechanism | Where it edits | Cold-connect floor | Failure-cost | HA-failover risk | Reversibility |
|----|-----------|----------------|--------------------|--------------|------------------|---------------|
| **A** | Extend userspace `PROBE_SCHEDULE_NS` to fire through 1800 ms | `neighbor_dispatch.rs:33` | Bounded by *kernel* `retrans_time_ms` — adding userspace probes only re-kicks the ICMP path; kernel ARP rate-limit still ~1/s. Likely floor: **~1.05 s** (one more kernel ARP cycle) | none | none — same `trigger_kernel_arp_probe()` syscall path, just at more time points | trivial — revert constant |
| **B** | Lower kernel `net.ipv4.neigh.default.retrans_time_ms` (and v6 equivalent) via sysctl from 1000 to 200-500 ms | systemd/operator config — *not* in userspace-dp | Floor: **~200-500 ms** (one kernel ARP retry interval) | kernel ARP table churn scales with delta-flows. Generally safe up to neighbor cardinality | none — kernel-wide setting, identical on both nodes | sysctl revert |
| **C** | Proactive neighbor warm at config-apply: for every `RouteSnapshot.next_hops` + every resolved BGP/OSPF next-hop + every IPsec peer, fire `trigger_kernel_arp_probe()` once, then let netlink monitor populate `dynamic_neighbors` | `coordinator/mod.rs::refresh_runtime_snapshot()` (or a tail-called helper) | Cold connect to a *known* next-hop becomes **~0 ms over the no-warm cost** — neighbor is already resolved before the first user flow arrives | failure of warming = same fall-through as today. Bounded by next-hop cardinality (handful) | **medium** — on RG-promote, an active node firing solicits could collide with old MAC entries on the upstream switch. Likely fine because solicit is unicast on known IP; but worth verifying | per-config knob revert |
| **D** | Lower `PENDING_NEIGH_TIMEOUT_NS` to ~800 ms + queue the original packet for the next TCP retransmit instead of dropping | `mod.rs:298` + `neighbor_dispatch.rs:100-103` | Avoids the original-SYN-drop case so we don't *waste* a successful resolution near the 2 s boundary. Standalone floor still bounded by kernel ARP retry | redo work if kernel resolves between 800 ms and 2 s; pair with A to keep solicit pressure on | low | constant revert |
| **E** | A+C combined: extend userspace probe schedule out to 1800 ms AND proactively warm at config-apply | both | Same as C for known next-hops (~0 ms over no-warm); same as A for unknown next-hops | minor — sum of A and C | as C | per-knob revert |

Where the kernel timing dominates: **per the Linux source (`net/core/neighbour.c::neigh_timer_handler` + `neigh_resolve_output`), each user-mode `sendto()` against an `INCOMPLETE` neighbor does *not* generate a new ARP frame on the wire unless `retrans_time` has expired since the last solicit was sent**. So option A's extra probes mostly serve as a heartbeat to keep the userspace-side queue alive — they don't accelerate kernel resolution beyond `retrans_time_ms`.

This is the central architectural insight that should drive the recommendation. The dominant lever for **unknown next-hops** is option B (kernel retrans timer); the dominant lever for **known next-hops** is option C (proactive warming, which happens once at config-apply and amortizes to 0 per flow).

## 6. Concrete design (recommended: C + B, then maybe A)

### C: Proactive neighbor warming at config-apply (highest leverage)

Site: tail of `Coordinator::refresh_runtime_snapshot()` in
`userspace-dp/src/afxdp/coordinator/mod.rs:435+`. After the new
`ForwardingState` has been published into `ha.forwarding` (so workers
will pick up resolved neighbors as soon as netlink fires), iterate the
new forwarding state and fire one warm probe per `(egress_ifindex,
next_hop)` whose neighbor is **not** already in
`forwarding.neighbors` AND **not** already in `dynamic_neighbors`.

Targets to warm (in priority order):

1. `forwarding.routes_v4.values().flat_map(|rs| rs.iter()).filter_map(|r| r.next_hop)` — static + BGP/OSPF/IS-IS routes (FRR has already populated these into the snapshot)
2. Same for `routes_v6`
3. Default routes specifically (the most-likely-to-be-hit destination)
4. Fabric peer IPs (`forwarding.fabrics.iter().map(|f| f.peer_addr)`)
5. Tunnel endpoints (`forwarding.tunnel_endpoints.values().map(|t| t.destination)`) — when the underlay neighbor matters

Implementation sketch:

```rust
// Coordinator::refresh_runtime_snapshot tail
self.warm_known_neighbors();

fn warm_known_neighbors(&self) {
    let snapshot = &self.forwarding;
    let mut seen: FastSet<(i32, IpAddr)> = FastSet::default();
    let already_resolved = |key: &(i32, IpAddr)| -> bool {
        snapshot.neighbors.contains_key(key)
            || self.neighbors.dynamic.contains_key(key)
    };
    let mut warm = |egress_ifindex: i32, hop: IpAddr| {
        if egress_ifindex <= 0 { return; }
        let key = (egress_ifindex, hop);
        if !seen.insert(key) { return; }
        if already_resolved(&key) { return; }
        if let Some(name) = snapshot.ifindex_to_name.get(&egress_ifindex) {
            trigger_kernel_arp_probe(name, hop);
        }
    };
    // Iterate routes_v4 / routes_v6 / fabrics / tunnel_endpoints
}
```

**Crucial design choice**: warm in a *spawned thread* off the
coordinator's hot path. `refresh_runtime_snapshot()` runs under the
single-threaded coordinator and we must not block it. `std::thread::spawn`
with a moved `Arc<…>` keyset is fine — netlink will deposit the results
into `dynamic_neighbors` regardless of which thread fired the probe.

Operator surface:

- `set chassis dataplane proactive-neighbor-warm <true|false>` — default
  `true` once shipped. Allow disable for operators who want strict
  manual-only neighbor populate (rare).
- Optional: per-VRF or per-next-hop opt-out via existing routing
  hierarchy, but **defer** — that's tier-2 surface.

### B: kernel `retrans_time_ms` operator knob

Site: `pkg/networkd/` or systemd unit files. Set
`net.ipv4.neigh.default.retrans_time_ms = 250` and
`net.ipv6.neigh.default.retrans_time_ms = 250` at daemon start, OR
via a sysctl drop-in file shipped with the deploy.

Why 250 ms not 200 ms: matches AF_XDP poll cadence (workers wake every
~1 ms but do real syscall work every ~10-100 ms). 250 ms keeps kernel
ARP rate well below socket churn while giving ~4× faster cold path
than today. 200 ms is also fine; pick whichever the reviewers prefer.

**Risk**: kernel ARP solicits scale with per-interface flow churn. For
the loss userspace cluster (~10 distinct next-hops), this is invisible.
For high-fanout deployments (thousands of neighbors), aggressive solicit
intervals can show up in DDoS-style ARP storms during route flap. The
**default-on** version of this should ship with a docs note for
high-fanout deployments to revert if observed.

### A (deferred behind C+B): extend userspace probe schedule

Add slots 500 ms, 1000 ms, 1500 ms, 1800 ms. Bounded by per-sweep dedup
already in place. Implementation is a one-line constant change.

**Why deferred**: per the kernel-source analysis in §5, extra userspace
solicits don't accelerate kernel ARP unless they cross a
`retrans_time_ms` boundary. With B at 250 ms, the userspace schedule
already has a fresh kernel solicit available between every existing
slot — so adding more slots adds heartbeat resilience but not raw
latency win. Worth doing as a follow-up; not the dominant lever.

### D (NOT recommended): re-queue after timeout

The proposal in the issue body — drop original packet at 800 ms and
re-queue on TCP retransmit — interacts poorly with TCP RTO timing. The
client retransmit at ~1 s would arrive against a still-pending neighbor
and we'd drop *that* too, then the second retransmit at ~3 s would
land. Net: same outcome as today, more code complexity.

If we're willing to lower `PENDING_NEIGH_TIMEOUT_NS`, the simpler move
is to lower it to a value > kernel `retrans_time_ms` + slop (i.e. with
B at 250 ms, drop the userspace timeout at 1500 ms). But still: if
kernel resolution hasn't happened by then, the client retransmit at
1 s won't have helped either. **Recommend not touching D in this PR.**

## 7. Public API preservation

- `Coordinator::refresh_runtime_snapshot()` keeps its existing signature
- `trigger_kernel_arp_probe()` unchanged
- `PROBE_SCHEDULE_NS` becomes a `static` slice (still constant);
  callsites unchanged
- New entry: `Coordinator::warm_known_neighbors()` — `pub(super)`,
  callable only from the coordinator
- Operator-visible CLI: one new knob (`proactive-neighbor-warm`).
  Default-on.

No protocol changes. No `ConfigSnapshot` schema changes (consumes
existing `routes` + `fabrics` + `tunnel_endpoints` + `neighbors` from
the snapshot; the empty `neighbors` case is the cold-start lever, and
warming explicitly skips already-resolved entries).

## 8. Hidden invariants the change must preserve

1. **No blocking call on the coordinator hot path**. Warm pass must be
   thread-spawned or non-blocking. The coordinator's
   `refresh_runtime_snapshot()` is single-threaded; it must return
   promptly so config-apply latency stays bounded.

2. **HA failover behavior**. On RG-promote, the new active node will
   re-run config apply (or at least observe state delta). The warm
   pass must not amplify failover latency. **Open question for
   reviewers**: should we suppress the warm pass on RG-promote events
   specifically? Or is the warm benefit (faster traffic recovery after
   GARP) the right behavior?

3. **Don't probe interfaces in transient down state**. Use
   `ifindex_to_name` lookup; if the interface is missing from the
   snapshot, skip silently.

4. **Don't loop-warm**. Single-shot per snapshot apply. Multiple snapshots
   per second are common; dedup against `dynamic_neighbors` + the
   per-call `seen` set means redundant snapshots cost almost nothing.

5. **Don't warm broadcast / multicast / loopback addresses**. Filter
   `next_hop.is_unspecified() || is_loopback() || is_multicast() ||
   is_broadcast()` before probing.

6. **`PENDING_NEIGH_TIMEOUT_NS` unchanged at 2 s**. Keep the safety
   margin; tests will verify acceptance gate is met without lowering
   the timeout.

7. **`PROBE_SCHEDULE_NS` unchanged for the C-only variant**. If
   reviewers push for A as well, extending it requires updating the
   `schedule_total_window_under_pending_neigh_timeout` test in
   `neighbor_dispatch.rs:557-567`.

## 9. Risk assessment

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | Warm pass is additive; failure mode is same as today (cold connect falls through to existing path) |
| Lifetime / borrow | LOW | New helper takes `&self` on coordinator; spawned thread captures cloned `Arc` keys |
| Performance regression | LOW (control plane) / NONE (data plane) | Adds N socket() + sendto() + close() at config-apply where N is unique-next-hop cardinality (handful). No hot-path edits |
| Architectural mismatch (#946/#961 dead-end pattern) | LOW | Mechanism is mechanically simple — fire existing function more places. No new data structures. No invariant inversion |
| HA failover impact | MEDIUM | RG-promote running warm pass could collide with upstream switch's GARP processing; needs explicit verification. **Mitigation**: gate warm pass on `ha.is_active()` or only run for owner-RG interfaces. Open question for reviewers |
| Kernel ARP storm | LOW | Bounded by neighbor cardinality + per-sweep dedup. For high-fanout deployments add operator opt-out |
| Acceptance gate met | MEDIUM-LOW | C alone targets known next-hops; if test scenario flushes neighbors WITHOUT a route to that neighbor in the snapshot (rare), C is moot. B alone gets to ~500 ms — possibly enough for the 200 ms gate, possibly not. **C + B should comfortably hit ≤200 ms for any next-hop the operator has configured**. Empirical verification required |

## 10. Test plan

- `make test` (Go + Rust full suites; no production code changes in C+B
  means no test count delta beyond new warm-pass tests)
- New unit tests in `coordinator/tests.rs`:
  - `warm_known_neighbors_fires_for_unresolved_next_hop`
  - `warm_known_neighbors_skips_already_resolved`
  - `warm_known_neighbors_skips_invalid_addresses` (multicast, loopback, unspecified)
  - `warm_known_neighbors_dedups_within_one_call`
  - `warm_known_neighbors_handles_missing_ifindex_to_name`
- New integration test: cold connect with proactive warming enabled
  measures < 200 ms on the loss userspace cluster (run as part of the
  diagnostic harness in the issue body)
- Existing `cold_start_probe_schedule_tests` mod tests pass unchanged
- Failover smoke: `make test-failover` baseline; must still complete in
  ≤60 ms

## 11. Out of scope (explicitly)

- Static neighbor entries via `set protocols nd …` — pre-existing path,
  not the dynamic learning path this issue targets
- IPv6 ND-specific edge cases (DAD, RA-derived next-hops) — separate
  follow-up
- The `forwarding.neighbors` static map itself — fine, this is
  dynamic-learning only
- Operator-tunable PROBE_SCHEDULE_NS itself (could expose as a knob;
  not needed for the win)
- Aggressive `PENDING_NEIGH_TIMEOUT_NS` reduction (option D)
- Cross-vendor NIC-specific timing (mlx5 vs i40e); the path is the same
- BPF map-based neighbor table tuning — userspace-only

## 12. Open questions for adversarial review

1. **Kernel-rate-limit claim**: is the §5 claim correct that userspace
   `sendto()` against an INCOMPLETE neighbor does not generate a new
   ARP unless `retrans_time` has expired? If wrong, option A's value
   rises significantly. Quote: kernel source `net/core/neighbour.c`
   path around `neigh_probe()` / `neigh_timer_handler()` / `neigh_event_send()`.

2. **RG-promote interaction**: should the warm pass run on the standby
   node? Or only on the active? The standby's `dynamic_neighbors` is
   warm via netlink monitor anyway; running on standby pre-populates
   for fast post-failover behavior at the cost of extra solicits.

3. **Acceptance-gate feasibility with B alone**: with kernel
   `retrans_time_ms = 250` and *no* proactive warming, what's the
   expected cold-connect floor? If it's well under 200 ms then option B
   alone is sufficient and C becomes the "additional polish" tier.

4. **Warm-pass cost on snapshot churn**: snapshots can come in at
   ~10/s during config storms; each snapshot can have ~100 routes
   in real deployments. Is N=100 socket()+sendto()+close() per snapshot
   acceptable as a one-shot? If reviewers think no, the alternative
   is "warm only on routes that *changed* since the last snapshot"
   which requires snapshot-diff tracking.

5. **The 2026-05-28 measurement is on a clean test cluster**. Does
   real-world traffic hit cold connect frequently enough to justify
   this work? E.g., NUD GC cycles `gc_stale_time = 60s`; STALE entries
   *do* keep working (the kernel queues new packets while sending a new
   solicit), it's only INCOMPLETE / FAILED that trips MissingNeighbor.
   How often do entries transition to FAILED in production? **If the
   answer is "almost never", reviewers may PLAN-KILL the whole effort
   in favor of just fixing the docs claim.**

6. **HA cluster correctness**: when the standby promotes, does the
   warm pass interact with GARP burst from `becomeMaster()`? GARP
   re-asserts our own MAC, warm pass would re-resolve *peer* MACs —
   no overlap on the surface, but verify with the cluster HA expert.

7. **Tunnel endpoints**: should we warm the *underlay* neighbor for
   tunnel endpoints? GRE / IPsec underlay neighbors are the typical
   place users see this latency, but the snapshot may not have the
   underlay route eagerly. Worth confirming with the routing-state
   expert.

## 13. Recommendation

Ship **B + C**. Defer **A** as a follow-up. **Do not ship D.**

Order of operations:
1. C (proactive warm at config-apply) — pure addition, low risk, large
   win for known next-hops
2. B (kernel retrans_time_ms 250 via sysctl drop-in) — operator-visible
   knob, covers the unknown-next-hop case
3. Verify on the loss userspace cluster: cold connect ≤ 200 ms (16×)
4. Update `docs/userspace-jit-design.md` with the new measured number
5. (Optional) A as follow-up if B alone doesn't get us under 200 ms

## 14. Reviewer convergence path

This is `/research` not `/engineer`. Convergence target: 3 of 3
(Claude SMR + Codex + AGY) on PLAN-READY for the recommended option
set, OR convergent PLAN-KILL with rationale that we file as
`labels/plan-kill` per the project's plan-kill discipline.

Copilot review will fire when the implementation PR opens, not now.
