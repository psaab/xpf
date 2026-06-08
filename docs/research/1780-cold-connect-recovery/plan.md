# #1780 — Cold-connect idle/overnight hang to data-path next-hops

**Status:** v3 — **CONVERGED** for Path A. Round-2: Codex PLAN-NEEDS-MINOR,
AGY PLAN-NEEDS-MINOR, Claude SMR PLAN-READY — all minors folded (cleanFailedNeighbors
in scope; guarded-goroutine+deadline+last-success not bare context.WithTimeout;
per-phase in-flight guards; phase-labeled gauge; regenDebouncer/warmNeighborCache
documented). Path A is PLAN-READY + committable; resolver/probe fix capture-gated.
**Branch:** `research/1780-cold-connect-recovery`
**Issue:** #1780 (residual after #1769 + #1771 Phases 1-2 / PR #1779)

## 0.1 Round-1 disposition (v2 — corrected + re-scoped)

| r1 finding (reviewer) | v2 disposition |
|---|---|
| **The "#1636 warmer driven every 15s" premise is WRONG** — Rust `queue_warm_pass` is event-driven (snapshot refresh `coordinator/mod.rs:724` + RG promotion `:907`), NOT periodic. The actual 15s periodic neighbor maintenance is **Go-side `runPeriodicNeighborResolution`** (`pkg/daemon/daemon_neighbor.go:353`) (Codex B). | **Path A retargeted to the Go periodic resolver.** The "neighbor cache warmup complete" log that stalled 17.5h is the Go loop, not Rust warm-pass. |
| **Path B first-probe-bypass aimed at the wrong delay** — the FIRST resolver request per key is already admitted (the 1s `last_resolved` limiter only suppresses *subsequent* requests, `neighbor_resolver.rs:563/630`); the first MissingNeighbor already probes immediately (`poll_descriptor:2174`) + at 10/60/260ms. The 100ms enqueue-throttle is per-binding → bypassing it amplifies across workers (Codex C, Claude SMR). | **Path B (first-probe-bypass) DROPPED.** The resolver/probe is already fast on the first attempt; the multi-second delay is elsewhere. |
| **No self-sustaining neg-cache stuck state** (Codex A confirms the resolved-wins check + evict-before-TTL). | Confirmed; removed from the hypothesis set. |
| **Root cause of the multi-second delay NOT established by code** — candidates: probe loss, raw-socket/probe failure, monitor/update loss, HA gating, or a genuinely silent `.200` (Codex A/D, Claude SMR). | **Capture is a HARD gate** for any resolver/probe fix; expanded to ARP tcpdump + full counter set (§8). |
| Don't wait for capture to fix factual errors; do wait for it to choose dominance (Codex D). | v2 fixes the errors now; the capture chooses which delay-source dominates. |
| Not PLAN-KILL; rewrite before implementation (Codex E). | v2 rewrite. |

**Corrected mechanism.** The Go `runPeriodicNeighborResolution`
(`daemon_neighbor.go:353`) is the 15s keep-warm loop (`resolveNeighbors` +
`forceProbeNeighbors` + `maintainClusterNeighborReadiness`→`warmNeighborCache`)
+ a 5s `cleanFailedNeighbors`. The first two handlers run **synchronously
inside the `for-select` loop**; `warmNeighborCache` runs in a goroutine guarded
by `neighborWarmupInFlight` (CAS true; `defer Store(false)`). **Stall modes:**
(1) a synchronous handler (`resolveNeighbors`/`forceProbeNeighbors`) that blocks
on a hung netlink/probe call **freezes the entire loop** — clean+resolve+probe
all stop (matches a total 17.5h stall); (2) `warmNeighborCache` hangs → the
goroutine never returns → `neighborWarmupInFlight` stuck true → every later
`maintainClusterNeighborReadiness` skips. Either way the periodic keep-warm
stops, neighbors age over overnight idle, and a cold connect drops into the
slow-resolution path.

## 1. Issue framing
Operator-confirmed: `iperf3 -c 172.16.80.200 -p5212 -P12` **hangs at connect
(0 bytes)** after hours/overnight idle; retries **stay hung a while then
self-recover**. The iperf3 *control* SYN is the cold SYN that hangs (data
streams never start). Persists after #1769 (neg-cache→resolver) and #1771
Phases 1-2 (per-key pending bound + ENOBUFS, PR #1779).

## 2. Code-walk: the mechanism is COMPOUNDING SLOWNESS, not a dead-end
Two hypotheses were **refuted** by reading the code/repro:
- *"warmer-off directly hangs"* — REFUTED: a 23-min warmer-off test showed
  `.200` oscillates REACHABLE↔STALE↔DELAY but never FAILED/absent (kernel
  retains the STALE MAC; no `gc_thresh` pressure), and the connect succeeded.
- *"resolver revokes-without-probing on an aged hop"* — REFUTED: `decide_action`
  probes on EVERY non-REACHABLE outcome — `Unconfirmed`→`ProbeOnStale`,
  `Failed`→`RevokeAndProbe`, `NoReply`→`ProbeOnly`, all calling
  `trigger_kernel_arp_probe` (`neighbor_resolver.rs:700-723`).

The real chain (cold connect to a FULLY-aged, both-sides-cold `.200` after
overnight):
1. First SYN → `MissingNeighbor` → not yet neg-cached → buffer 1 pkt + probe.
2. If `.200` (both-sides-cold) doesn't ARP-reply within `PENDING_NEIGH_TIMEOUT`
   (2s) → buffered pkt times out → **neg-cache arms** (3s TTL).
3. Retransmit SYNs → neg-cache fast-fail → resolver single-key GET+probe,
   **per-key rate-limited** (1s `last_resolved` window) + per-binding
   enqueue-throttled (100ms).
4. Resolution eventually completes, but the connect only establishes when a
   **TCP SYN retransmit lands AFTER resolution**. TCP SYN backoff is
   1,2,4,8,16s — so even ~3-5s resolution pushes the successful SYN to ~7-15s,
   and any probe/ARP loss compounds it → "hangs for a while," then recovers.

**Why overnight specifically:** the #1636 neighbor-warmer normally keeps the
data-path next-hops REACHABLE every ~15s, so they never age and step 1 never
fires. The warmer was observed **stalled** (last run 13:35:30Z + a 17.5h
overnight gap, daemon NRestarts=0, correlating with a failover/peer-disconnect
event). With the warmer stalled across overnight idle, `.200` eventually fully
ages (kernel GC + `.200`'s side aging) → drops into the slow-resolution chain.

## 3. Honest scope/value
This is an availability bug (cold connects stall 10-30s+ after overnight). The
fix is multi-factor; **PLAN-KILL is acceptable** if reviewers judge the warmer
fix alone sufficient or the resolver tuning too risky for the hot path. The
smoking-gun capture (resolver counters during a real hang) should confirm which
factor dominates before code.

## 4. What's already shipped
- #1769: neg-cache fast-fail → shared resolver (single-key GET + probe-on-all-
  non-REACHABLE + epoch-guarded cache).
- #1771 Phases 1-2 (PR #1779): per-key pending bound + ENOBUFS no-absent-key
  re-dump.
- #1636: neighbor-warmer (`queue_warm_pass`, coordinator-driven, 15s, gated
  `skips_when_owning_rg_inactive`).

## 5. Path options (v2 — Path A committable now; resolver-fix diagnostic-gated)

**Path A — Go periodic-resolver stall-hardening (prevention; PRIMARY,
committable, root-cause-independent).** A periodic neighbor-maintenance loop
that can be frozen 17.5h by one hung handler is a bug **regardless** of the
cold-connect hang. Harden `runPeriodicNeighborResolution` (`daemon_neighbor.go:352`):
- **Supervise EACH periodic phase from the loop with a guarded goroutine +
  deadline + last-success/last-start timestamp + skip-if-still-in-flight**
  (Codex r2: `context.WithTimeout` alone is insufficient — the netlink/probe
  callees don't honor context, so a timeout can't cancel a stuck syscall; the
  guarded-goroutine keeps the `for-select` loop alive without pretending to
  cancel). Phases to isolate: **`resolveNeighbors`, `forceProbeNeighbors`, AND
  `cleanFailedNeighbors`** (Codex+AGY: `cleanFailedNeighbors` is also
  synchronous + netlink-heavy at `:293`, so leaving it inline still leaves a
  loop-freeze vector). Per-phase in-flight atomics (`resolveNeighborsInFlight`,
  `forceProbeInFlight`, mirroring `neighborWarmupInFlight`) prevent overlapping
  goroutines + netlink-socket leakage if a prior pass is hung (AGY).
- **Watchdog the in-flight guards**: a stuck guard (hung phase) must not wedge
  that phase forever — re-launch after the deadline elapses (bounded relaunch),
  so a transient hang self-heals.
- **Add a phase-labeled `neighbor_periodic_last_success_age_seconds{phase=...}`
  gauge** (Codex r2: phase-labeled last-success/age, NOT per-family — record
  per-phase pass completion). This is the fix's observability AND the live
  diagnostic the capture needs. (Only metric Path A adds; not #1771 §2.6.)

If the periodic loop reliably keeps the data-path next-hops warm, the
cold-connect path never triggers — the highest-leverage, lowest-risk fix.

**Additional stall vectors (AGY r2) — documented, scoped:**
- **`regenDebouncer`** (`daemon_neighbor_listener.go:171`→`RegenerateNeighborSnapshot`
  :203 → synchronous `LinkByName`/`NeighList`, `neighbors.go:185`): a netlink
  hang freezes event-driven snapshot regen (not the main loop). Apply the same
  guarded-goroutine+deadline treatment OR explicitly note as a separate
  follow-up if out of Path A's scope.
- **`warmNeighborCache` UDP-probe flood** (`daemon_ha.go:1081`): sends a 1-byte
  UDP-to-port-1 per unique src/dst IP across ALL sessions — under high session
  counts this looks like a port scan to external hosts and is redundant for
  routed/gateway traffic (only on-link IPs need per-IP ARP warming). NOT a
  Path A fix; flagged as a future scoping follow-up (own issue).

**Resolver/probe fix — DEFERRED, diagnostic-gated.** Round-1 established the
resolver already probes immediately on the first cold fast-fail and the 1s
limiter does NOT block it, so the "first-probe-bypass" idea is dropped. IF the
capture (§8) shows the multi-second delay is in resolution itself (not the
warmer-off aging), the fix target will be whichever the data names —
probe-loss / raw-socket failure / monitor-update loss / HA gating / silent peer
— NOT a blanket rate-limit bypass. No resolver-path code is proposed until the
capture pins the dominant delay source. (Storm-safety note for any future probe
change: cap one immediate probe per `(ifindex, hop)` cold epoch centralized in
the resolver, never a per-binding bypass.)

**Recommendation:** ship **Path A** now (independently-correct stall fix +
watchdog gauge); treat the resolver/probe fix as a **separate, capture-gated**
follow-up.

## 6. Public API / invariants
- Hot path stays cheap: all changes are on the `MissingNeighbor` / resolver
  slow path or the warm-pass driver — never per-forwarded-packet.
- Path A must NOT change WHAT is warmed/cleaned (no standby-RG warming, no new
  probe targets) — only HOW the loop is supervised (guard + deadline + relaunch).
  The 5s/15s cadences and per-phase target sets are preserved.
- Per-phase guards must not allow overlapping passes (netlink-socket leak); each
  phase relaunches only after the prior pass returns or its deadline elapses.

## 7. Risk
| Class | Level |
|---|---|
| Behavioral regression | MED — touches the cold-connect + warm-pass paths (HA-adjacent) |
| Hot-path perf | LOW — slow-path / control-plane only |
| HA | **MED** — warm-pass gating is cluster-state-coupled; `make test-failover` gating |
| Architectural | LOW — extends #1769/#1771/#1636 mechanisms |

## 8. Test plan
- Unit: a hung phase handler (injected blocking netlink/probe) does NOT freeze
  the `for-select` loop — the next tick still fires and the other phases still
  run; the in-flight guard relaunches the hung phase after its deadline; the
  `neighbor_periodic_last_success_age{phase}` gauge advances for healthy phases
  and grows for the stuck one (so a stall is observable). No overlapping passes.
- **Live repro (the hard part) + dominance capture:** overnight-scale idle then
  a cold connect, capturing (Codex D) — **ARP/NDP tcpdump on the egress**
  (is `.200` silent, or is the firewall not soliciting?), `neighbor_pending_*`
  (timeout_drops, dwell, max_depth), resolver `get_attempts`/`get_resolved`/
  `probe_on_stale`/`get_failures`/`epoch_rejects`/enqueue_drops/disconnected,
  the new `neighbor_periodic_last_pass_age` gauge (Path A), HA
  `forwarding_active`/`lease_until`, and the Go 15s neighbor logs. This names
  the dominant delay source: warmer-stalled-and-aged (Path A) vs
  resolver/probe/monitor/HA (the deferred resolver-fix target) vs silent peer.
  Captures: `/tmp/idle-hang-longcapture.out` (running) + the operator's overnight
  capture.
- `make test-failover` (warm-pass gating is HA-coupled) — gating.
- Smoke matrix unaffected (slow-path change).

## 9. Out of scope
- #1771 §2.1 per-key epoch (Phase 4, separately gated on `epoch_rejects`).
- #1771 §2.6 counters (separate follow-up) — though the phase-labeled
  `neighbor_periodic_last_success_age{phase}` gauge belongs in Path A.

## 10. Open questions (round-2 RESOLVED — kept for record)
1. ~~Path B vs Path A dominance~~ — Path B dropped; the capture now only gates
   the SEPARATE deferred resolver/probe fix (names silent-peer vs probe-loss vs
   monitor/HA), not Path A.
2. **Which exact phase hung for 17.5h** — `resolveNeighbors` /
   `forceProbeNeighbors` / `cleanFailedNeighbors` (loop-freeze) or
   `warmNeighborCache` (guard-wedge)? The phase-labeled gauge + the capture's
   journal will name it; Path A hardens all of them regardless.
3. ~~first-probe-bypass safety~~ — DROPPED (the first probe is already
   immediate; the limiter only throttles subsequent; bypass risks amplification).
4. Is the "a while" purely TCP-SYN-backoff-compounding after warmer-off aging,
   or a genuine resolver/probe stall? **Capture-gated** for the deferred
   resolver fix — does NOT block Path A.
5. Scope: `regenDebouncer` hardening (same vector) and `warmNeighborCache`
   UDP-flood scoping — fold into Path A or split as follow-ups? (AGY r2.)
