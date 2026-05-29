# Plan of Action — #1651 cold-resolve latency (REOPENED)

- **Revision:** v2 (SMR-r1 findings folded in)
- **Branch:** `research/1651-cold-resolve-latency`
- **Base:** origin/master @ `a107e7489`
- **Issue:** #1651 (reopened 2026-05-29 on operator feedback: *"it still
  is quite a long time for new connections to run when the ARP and
  neighbor caches are empty."*)
- **Mode:** `/research` — stops at PLAN-READY/PLAN-KILL. No PR. No
  production code touched. (Throwaway instrumentation was deployed for
  Gate-M', measured, then fully reverted; cluster restored to clean
  origin/master binary — see §3.)

---

## §0. TL;DR / Recommendation

**Gate-M' (the decider) was run FIRST.** Direct dataplane instrumentation
on the live `loss:xpf-userspace-fw0/fw1` cluster, across all four cells
the reopen demanded, shows:

| Cell | Cold connect (LIVE target) | Mechanism |
|------|---------------------------|-----------|
| on-link v4 (ARP) | **1.45–6.1 ms** (median ~2.9 ms), 12 trials | kernel ARP + buffer re-drive |
| on-link v6 (NDP) | **1.29–8.96 ms** (median ~2.8 ms), 12 trials | kernel NDP + buffer re-drive; no DAD penalty |
| routed v4 (ext 8.8.8.8 via gw) | **2.71–7.4 ms** (one 28 ms warmup), 12 trials | gateway resolve (warmer-eligible) |
| routed v6 (gw NDP) | **3.5–19 ms** (one 78 ms warmup), 6 trials | gateway resolve |
| post-HA-failover, on-link v4 | **6.5 ms then sub-2 ms**, 8 trials | fw0 took over, cold WAN cache |

The dataplane **`MissingNeighbor` buffer path is exercised** (confirmed via
throwaway `GATEM1651 QUEUE`/`REDRIVE` counters: 45+ QUEUE events across
trials). The **queue→re-drive latency is 0 µs – ~2 ms** (worst single
outlier ~26 ms). The **800 ms `pending_neigh_timeout_ns` drop path was
NEVER hit for any live target** (0 `DROP_TIMEOUT` events across the live
cells).

**The ~800 ms slow path reproduces only for DEAD / non-responding
destinations** — connecting to 20 distinct unused on-link IPs
(`172.16.80.120–139`, no host answers ARP) produced a uniform **~800 ms**
per connect, with `GATEM1651 DROP_TIMEOUT ... held_us≈800740 attempts=3`
(all three re-probes exhausted, then drop at the fast-timeout). This is
the `PENDING_NEIGH_TIMEOUT_FAST_NS = 800_000_000` ns drop
(`forwarding_build/mod.rs:401`) firing because the host genuinely never
ARP-replies.

**Recommended disposition: Path C (do-nothing on the dataplane resolve
mechanism) + one small, defensible lever if the user wants it (Path B1).**
The headline "~1 s vs ~1 ms" framing is NOT reproducible for live targets
on this cluster — live cold connect is already 1–9 ms. The only ~800 ms
case is unreachable destinations, where ~800 ms-then-drop is arguably
correct (you cannot forward to a host that will not answer ARP/NDP), and
is intentionally tuned to fire *before* the client's first 1 s TCP RTO so
the client's SYN-retransmit lands on a fresh queue.

**Path A (active dataplane XSK-TX resolution) is NOT justified by the
measured data** — it would eliminate a kernel round-trip that is already
sub-millisecond on this cluster, at the cost of a substantial new
ARP/NDP-synthesis + RX-parse + dedup-vs-kernel subsystem. It remains a
*conditional* option only if the user can produce a reproduction on a
different topology (i40e PF-passthrough standalone VM, or a high-RTT WAN
link) where the kernel resolve itself is the dominant term. See §6.

**#1648 is NOT subsumed and stays open** (§9): it is the seq=0 startup
neighbor-dump race, orthogonal to steady-state resolve latency. Path A
*would* make cold targets independent of the kernel startup dump, but
since Path A is not recommended, #1648 keeps its own scope.

---

## §1. Problem statement & operator claim

The operator reports new connections are slow "when the ARP and neighbor
caches are empty." The reopen (issue comment) correctly faulted the prior
close for two reasons: (1) the prior Gate-M measured only on-link v4
`172.16.80.200` and may have hit a retained stale entry; (2) it dismissed
active resolution by conflating the deleted `send_raw_frame` helper with
the *capability*. This research re-measures all four cells under
truly-cold conditions and re-opens the active-resolution design question.

The cold-resolve control flow (verified against origin/master @ `a107e7489`):

1. Forwarding decision returns `MissingNeighbor`
   (`poll_descriptor/mod.rs:2379`). The SYN frame is buffered into
   `binding.pending_neigh` (cap `MAX_PENDING_NEIGH = 4096`,
   `mod.rs:342`) with `queued_ns = now_ns`, `probe_attempts = 0`
   (`poll_descriptor/mod.rs:2644-2660`).
2. `trigger_kernel_arp_probe(name, next_hop)` fires once per
   `(egress_ifindex, next_hop)` (dedup via `pending_neigh.iter().any`,
   `mod.rs:2416`). It opens an `AF_INET`/`AF_INET6` `SOCK_RAW` ICMP/ICMPv6
   socket and `sendto`s an echo to the next-hop, which makes the **kernel**
   emit the ARP/NDP solicitation (`neighbor.rs:36-99`). `send_raw_frame`
   is a DELETED tombstone — only a dangling doc comment remains
   (`neighbor.rs:275`). Confirmed.
3. The kernel resolves; the resolution arrives as an RTM_NEWNEIGH netlink
   multicast, consumed by `neigh_monitor_thread` (`neighbor.rs:465`) →
   `parse_neighbor_msg` (`neighbor.rs:297`) → `update_dynamic_neighbor`
   into the shared `ShardedNeighborMap`.
4. `retry_pending_neigh` (`neighbor_dispatch.rs:47`) runs EVERY poll tick
   — both on the RX-empty branch (`worker/lifecycle.rs:135`) and post-RX
   (`:296`). It re-checks `forwarding.neighbors` then `dynamic_neighbors`
   for the `(egress_ifindex, next_hop)` key; on hit it re-drives the
   buffered frame to TX. On miss it re-probes per
   `PROBE_SCHEDULE_NS = [10 ms, 60 ms, 260 ms]`
   (`neighbor_dispatch.rs:33`) via `probe_due` (`:41`).
5. If still unresolved at `pending_neigh_timeout_ns`, the frame is
   dropped + recycled (`neighbor_dispatch.rs:110`). The timeout is 800 ms
   when every dataplane iface's kernel `retrans_time_ms ≤ 300 ms`
   (`PENDING_NEIGH_TIMEOUT_FAST_NS`, `forwarding_build/mod.rs:401,411`),
   else the 2 s `PENDING_NEIGH_TIMEOUT_NS` fallback (`mod.rs:329`). The
   800 ms value is deliberately below the client's first ~1 s TCP RTO.

**Poll-tick cadence (re-drive granularity floor).** Deployed mode is
`--poll-mode interrupt` (verified on the cluster process args + in
`docs/ha-cluster-userspace.conf:288`). In interrupt mode the worker, when
idle, spins `IDLE_SPIN_ITERS = 256` (`mod.rs:284`) then blocks on
`libc::poll(interrupt_poll_fds, INTERRUPT_POLL_TIMEOUT_MS = 1 ms)`
(`worker/loop_body/mod.rs:1371-1389`, `mod.rs:286`). **The poll set
contains ONLY the XSK device fds** (`loop_body/mod.rs:169-180`) — the
netlink monitor socket is NOT in it. So after the kernel resolves and the
monitor thread updates `dynamic_neighbors`, the worker re-drives on the
next poll wake, at most ~1 ms later. The re-drive granularity floor is
≈1 ms — **not** the ~1 s the issue's headline implies. The Gate-M'
`REDRIVE latency_us` distribution (0–~2000 µs typical) confirms this.

---

## §2. Gate-M' — full measurement (THE DECIDER)

**Method.** Throwaway always-on eprintln instrumentation was added at three
points and measured, then reverted:
- `poll_descriptor/mod.rs` MissingNeighbor buffer site → `GATEM1651 QUEUE
  t=… egress_if=… next_hop=… qlen=…`
- `neighbor_dispatch.rs` re-drive success → `GATEM1651 REDRIVE t=…
  queued=… latency_us=… attempts=…`
- `neighbor_dispatch.rs` drop-at-timeout → `GATEM1651 DROP_TIMEOUT …
  held_us=… attempts=…`

Per trial: `ip neigh flush all` + `ip -6 neigh flush all` on the **active
owner** (and on the client, to avoid counting the client→firewall LAN
resolve), 0.4 s settle, then a timed `socket.connect()` from
`cluster-userspace-host` (10.0.61.102). The flush was verified to emit
RTM_DELNEIGH (`Deleted … FAILED` in `ip monitor neigh`), which the
dataplane monitor consumes as `29 => remove_dynamic_neighbor`
(`neighbor.rs:359`), so `dynamic_neighbors` is genuinely cleared — closing
the prior Gate-M's "retained stale entry" blind spot.

**Truly-cold verification.** The proactive neighbor warmer
(`coordinator/mod.rs:585 queue_warm_pass`) warms **route next-hops only**
(gateways) — it iterates `routes_v4/_v6` `route.next_hop` (`:713-723`),
skips already-resolved entries (`:651`), and is HA-RG-gated (`:656-663`).
On-link /24 destinations are reached via a scope-link route with
`next_hop = None`, so **arbitrary on-link host IPs are NOT pre-warmed** —
my on-link host flushes were genuinely cold. Confirmed: the dataplane
buffered each cold connect (`GATEM1651 QUEUE` fired).

**Active owner discipline.** The cluster's active RG owner moved between
nodes during the session (restarts trigger failover). All latency cells
were measured against whichever node held the WAN VIP `172.16.80.8` at the
time, with the instrumented binary deployed to BOTH nodes.

### Results

Live-target cells (≥6–12 trials each) — see §0 table. Summary:
- on-link v4 / v6, routed v4 / v6, and post-failover: **all 1–9 ms** for
  live targets (a handful of first-connect warmups at 28–78 ms).
- `GATEM1651 REDRIVE latency_us`: predominantly **0 µs** (resolved within
  the same poll cycle the SYN was buffered) and **351–471 µs**; worst
  single outlier **~26 ms**. `egress_if=14` = the **logical VLAN ifindex**
  (ge-7-0-2.80), reconfirming there is no physical-parent-vs-logical
  ifindex key mismatch on this kernel/driver.
- `GATEM1651 DROP_TIMEOUT`: **0 events** across all live cells.

Dead-target sweep (20 distinct unused on-link IPs, back-to-back):
- Uniform **~768–832 ms** per connect.
- `GATEM1651 DROP_TIMEOUT … held_us≈800740 attempts=3` for each — the
  800 ms fast-timeout drop after all 3 re-probes are exhausted.

### Supplementary measurements (SMR-r1 hardening)

- **Firewall-local ARP RTT (grounds the 0 µs REDRIVE):** on the active
  owner, `ip neigh flush all` then `ping -c1 172.16.80.200` =
  **time=0.496 ms** (first packet, includes the ARP resolve); `ip monitor
  neigh` shows the target REACHABLE essentially immediately. So the
  on-link kernel resolve is ~0.5 ms — a 0 µs queue→re-drive (resolve
  completing inside one ≤1 ms poll cycle) is physically consistent, not an
  artifact of a non-flushed `dynamic_neighbors`.
- **Dead-host client SYN pattern (the reopen item-4 distinction):** client
  pcap to a dead on-link host (`172.16.80.150`) shows **exactly ONE SYN**,
  then the firewall holds it and drops at ~800 ms; the client `connect()`
  returns at **805 ms**. It is a single held SYN dropped at the firewall's
  fast-timeout — NOT a dropped-SYN → client-RTO storm. (At 800 ms the
  client has not yet reached its first ~1 s TCP RTO, which is exactly why
  the 800 ms fast-timeout is tuned below 1 s.)
- **Routed-cell caveat (scoping, per SMR HOSTILE-1):** the routed cells
  (8.8.8.8, gw NDP) resolve a **gateway** next-hop, which IS
  warmer-eligible (`queue_warm_pass` warms route next-hops). Those cells
  may reflect a warmer-kept-warm gateway rather than a truly-cold resolve.
  **The conclusion therefore rests on the on-link host cells** (v4/v6),
  whose next-hop is the destination host itself — NOT warmer-eligible, and
  verified buffered (`GATEM1651 QUEUE` fired per connect). The routed cells
  are corroborating-but-not-load-bearing.

### Interpretation

1. **For live targets the dataplane cold-resolve path is already fast
   (1–9 ms) on this cluster and the 800 ms drop never fires.** The
   issue's "~1 s" is not reproducible for reachable destinations.
2. **The only ~800 ms case is unreachable destinations**, where the host
   never ARP/NDP-replies. ~800 ms-then-drop is the designed behavior, and
   is intentionally < the client's first ~1 s TCP RTO so the client's SYN
   retransmit lands on a fresh queue rather than a still-pending one.
3. The re-drive granularity (≤1 ms poll-wake) and the kernel resolve RTT
   (sub-ms on this LAN) are both small; neither is a defect.

---

## §3. Cluster restoration (no production change)

- Throwaway instrumentation reverted (`git checkout` of the two files;
  `git diff --stat` clean).
- userspace-dp rebuilt from clean source (`cargo build --release`),
  redeployed to BOTH nodes, daemons restarted, forwarding reconfirmed
  (`ping 172.16.80.200` OK), and `strings … | grep GATEM1651` = 0 on the
  deployed binary. The cluster is back on a source-identical
  origin/master build. (CoS re-apply, if the user later smokes, is the
  normal post-deploy step per CLAUDE.md.)

---

## §4. Blast radius of the candidate fixes

- **Path A (active resolution):** new ARP/NDP frame synthesis on the XSK
  TX ring, classify_arp/NDP off the RX ring, neighbor program +
  dedup-vs-kernel. Touches `poll_descriptor`, `neighbor*`, `frame/`,
  `tx/dispatch`, RX classify, and the UMEM frame-ownership rules. Large,
  cross-cutting, HA-sensitive. ~several hundred LOC + new tests.
- **Path B (levers):** `PROBE_SCHEDULE_NS` retune and/or a netlink-socket
  add to the worker poll set and/or a tight kernel-neigh poll. Small
  (tens of LOC), localized to `neighbor_dispatch.rs` +
  `worker/loop_body`.
- **Path C (do-nothing):** zero LOC.

---

## §5. Goals / non-goals

- **Goal:** decide, from measured evidence, whether the cold-resolve path
  has a real per-connect latency defect on the supported dataplane, and
  if so which mechanism fixes it at acceptable cost.
- **Non-goal:** changing the behavior for genuinely unreachable
  destinations (the 800 ms-then-drop is intended and bounded).

---

## §6. Multiple Path Options (the menu for the user)

### Path A — Active dataplane resolution (XSK-TX solicitation + RX-parse)
The dataplane crafts the ARP request / NDP solicitation, TXes it on the
XSK ring itself, parses the reply off the RX ring (`classify_arp` already
runs on RX in `poll_stages`), and programs `dynamic_neighbors` (and
optionally the kernel via `program_kernel_neighbor`, RTM_NEWNEIGH,
`neighbor.rs:~211`). Eliminates the kernel-probe → kernel-resolve →
netlink-multicast → monitor-learn round-trip.

- **Claimed win:** the issue's "~1 ms vs ~1 s." **Measured reality:** the
  kernel round-trip it removes is already sub-millisecond on this cluster
  (REDRIVE latency 0–2 ms). So Path A's expected win here is < 1 ms — not
  worth the subsystem.
- **Hostile open questions (must answer before any A work):**
  - NDP requires the solicited-node multicast group, the correct
    source link-local address per egress (VLAN sub-iface!), and a correct
    ICMPv6 pseudo-header checksum. ARP requires correct sender HA/PA.
  - **Double-resolve race vs the kernel:** the kernel ALSO resolves (the
    SYN reinjection / the `trigger_kernel_arp_probe` path). Active TX
    would race it; both program the same neighbor. Need a clear ownership
    rule and idempotent program.
  - **UMEM frame ownership:** which worker/binding owns the solicitation
    frame; the per-queue UMEM ownership rule (#959 decomposition) must not
    be violated. A solicitation TX from an arbitrary worker for a
    different egress binding is exactly the cross-binding hazard.
  - Retransmit/backoff for the active path (re-implements what
    `PROBE_SCHEDULE_NS` already does for the kernel path).
  - VLAN demux on TX/RX in zero-copy mode (the historical reason the
    XDP_PASS reinject was abandoned — `poll_descriptor/mod.rs:2640-2643`).
- **Recommendation:** **conditional KILL.** Only revisit if the user
  produces a reproduction (i40e PF-passthrough standalone VM, or a
  high-RTT WAN next-hop) where the *kernel resolve itself* is the
  dominant multi-hundred-ms term. On the supported smoke cluster it
  solves a non-problem.

### Path B — Cheaper levers
- **B1 — add the netlink monitor socket to the worker poll set.** Today
  the worker blocks up to 1 ms on XSK fds only; a resolved-neighbor
  netlink event does not wake it. Adding the monitor fd (or an eventfd
  the monitor thread signals) to `interrupt_poll_fds` would re-drive
  *immediately* on resolution instead of on the next ≤1 ms poll wake.
  **Measured headroom: ≤1 ms.** Small, clean, defensible as a latency
  polish — but the win is within measurement noise. Optional.
- **B2 — retune `PROBE_SCHEDULE_NS`** (e.g. 2/8/30 ms). Only helps when
  the *first* kernel solicitation is dropped and a faster re-probe
  matters. Not observed in Gate-M' (live targets resolved on attempt 0).
  Marginal; risks probe-storm on dead-host bursts (the dead-target sweep
  already fires 3 probes per host — tightening multiplies socket churn).
- **B3 — dead-host fast-fail / negative cache (NAMED operator choice).**
  The ~800 ms case IS what an operator would perceive as "new connections
  are slow when caches are empty" IF their new connections frequently
  target hosts that do not answer ARP/NDP (momentarily down hosts, an
  ARP-dropping firewall in front, a stale ARP-proxy, scan-like traffic).
  An operator does not distinguish "live-but-cold" (fast) from
  "dead/non-responding" (800 ms). Options under B3:
  - Lower `PENDING_NEIGH_TIMEOUT_FAST_NS` — fails dead-host connects
    faster, but risks dropping a live-but-slow host before it resolves.
    Bounded by the < 1 s TCP-RTO design constraint.
  - Add a short-lived **negative cache** keyed on `(egress_ifindex,
    next_hop)` so a *repeat* connect to a recently-failed host fails fast
    (e.g. immediate ICMP-unreachable or fast drop) instead of re-buffering
    + re-probing for another 800 ms. This is the more operator-friendly
    variant and does not regress the live-but-slow case (it only
    short-circuits hosts that *already* failed to resolve).
  **This is a real, scoped option — not pre-dismissed.** Whether to ship
  it depends on the operator's answer to the §10 reachability question.

### Path C — Do nothing on the resolve mechanism
Gate-M' shows live cold connect is already 1–9 ms. Close #1651 as
"not reproducible for live targets on the supported dataplane; ~800 ms is
unreachable-destination behavior and is correct + bounded." Keep #1648
open for the orthogonal startup-dump race.

---

## §7. Recommended plan

**Action item before close (SMR HOSTILE-5):** ask the operator (a) which
environment exhibits the slow connects (i40e PF-passthrough standalone VM?
the loss userspace cluster? production?), and (b) whether the slow
destinations are **reachable** (do they eventually answer ARP/NDP) or
unreachable. This one question routes the disposition: reachable+slow on a
different topology → re-measure there (possibly Path A); unreachable →
Path B3; reachable+fast everywhere → Path C close.

**Primary (given the loss-cluster evidence): Path C** (do-nothing on the
resolve mechanism), because the operator's "long time" does not reproduce
for live targets here and the only slow path is dead-host behavior.

**Optional polish if the user wants a defensible latency win: Path B1**
(monitor-fd in the worker poll set), accepting that the measured headroom
is ≤1 ms. This is the only change with a real (if tiny) mechanism behind
it and no behavioral risk.

**If the user can reproduce ~1 s on a different topology:** reopen the
Path A design with the §6 hostile questions answered and a fresh Gate-M'
on that topology as the gate.

---

## §8. Validation plan (for whichever path /engineer picks)

- Path C: none (close-out); the Gate-M' transcript in this doc is the
  evidence.
- Path B1: re-run the §2 Gate-M' matrix before/after; assert the REDRIVE
  latency distribution shifts toward 0 and no behavioral regression; run
  `make test-failover` (touches the worker loop / poll set). Smoke on the
  loss userspace cluster (v4+v6 × push/-R × CoS-off/on per the standing
  smoke rules).
- Path A (only if revived): full differential + property tests for
  ARP/NDP synthesis + checksum, double-resolve idempotence, UMEM
  ownership, VLAN demux; `make test-failover`; full smoke.

---

## §9. #1648 interaction

#1648 is the **seq=0 startup neighbor-dump race** (the first connect after
daemon restart / long idle, where `request_neighbor_dump` races a flush).
Gate-M' post-failover first-connect was **6.5 ms** (fast) on this cluster
— the ~1.7 s the prior research saw was a startup-window transient for a
*specific* entry, not a per-connect defect. #1648 is **orthogonal** to the
steady-state resolve latency this issue is about. **#1648 is NOT
subsumed** and stays open with its own scope. (Path A, if it ever ships,
*would* make cold targets independent of the kernel startup dump, which is
the only path under which subsumption would apply — but Path A is not
recommended.)

---

## §10. Risks / unknowns

- **Topology generalization:** all measurement is on the mlx5 SR-IOV-VF
  loss cluster (native XDP, low-RTT LAN). The operator may be on the i40e
  PF-passthrough standalone VM or a high-RTT WAN. The conclusion ("live
  cold connect is fast") is proven only for the smoke cluster. If the
  operator's environment differs materially, a fresh Gate-M' there is
  required before concluding. This is the single biggest residual risk and
  the reason Path A is "conditional KILL," not "KILL."
- **The 800 ms dead-host path** is by design; changing it (B3) trades
  dead-host fail-fast against live-but-slow-host correctness.

---

## §11. Decision matrix

| Gate-M' outcome | Disposition |
|-----------------|-------------|
| Live cells all 1–9 ms, DROP_TIMEOUT only on dead hosts (**OBSERVED**) | **Path C** (+ optional B1); KILL Path A; #1648 stays open |
| Live cells show a reproducible ~1 s with DROP_TIMEOUT on a LIVE host | investigate why the live host's kernel resolve is slow; B1/B2 or Path A conditional |
| Kernel resolve itself dominant (high-RTT next-hop) | Path A becomes viable; answer §6 hostile Qs first |
| Slow ONLY post-restart | that is #1648, not #1651 |

**Observed row: Path C (+ optional B1).**
