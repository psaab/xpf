# #1780 — Cold-connect idle/overnight hang to data-path next-hops

**Status:** DRAFT v1 — pending 3-way hostile plan-review (Codex + AGY + Claude SMR)
**Branch:** `research/1780-cold-connect-recovery`
**Issue:** #1780 (residual after #1769 + #1771 Phases 1-2 / PR #1779)

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

## 5. Path options (multi-factor — likely ship BOTH A+B)

**Path A — Warmer reliability (prevention; primary).** Find why
`queue_warm_pass` stopped being driven for 17.5h after a peer-disconnect with
the daemon up (NRestarts=0). Candidate: the coordinator tick that drives warm
passes is gated on a cluster-sync/RG-active state that stays stuck after
failover churn. Fix: make the warm-pass driver resume reliably after HA events
(+ a `neighbor_warm_last_pass_age` gauge / watchdog so a stalled warmer is
observable). If the warmer keeps `.200` REACHABLE, the cold-connect path never
triggers — the highest-leverage fix.

**Path B — Fast cold-connect resolution (recovery; the #1771 §10a part).**
When aging DOES occur, make recovery sub-second so the first/second TCP SYN
lands post-resolution instead of compounding to 10-30s:
- On a FRESH cold key (first fast-fail), probe IMMEDIATELY — bypass the 1s
  `last_resolved` rate-limit + 100ms enqueue-throttle for the first
  GET/probe per key (§2.3 cross-sweep backoff: aggressive early, then back
  off). The throttles exist to prevent SYN-storm probe amplification; an
  exception for the first probe per cold key is safe (one probe).
- Optionally don't let the first buffered SYN time out into the neg-cache
  before the probe has had a chance (couple the 2s `PENDING_NEIGH_TIMEOUT`
  with the probe schedule).
- §2.4 negative-keeps-probing: a neg-cached key keeps the resolver GET/probe
  on the backoff so it resolves promptly (already probes — tighten cadence).

**Path C — Both A+B (recommended, pending capture).** A prevents the common
case; B bounds the worst case when prevention lapses.

## 6. Public API / invariants
- Hot path stays cheap: all changes are on the `MissingNeighbor` / resolver
  slow path or the warm-pass driver — never per-forwarded-packet.
- Warmer fix must not warm on a standby RG (preserve `skips_when_owning_rg_inactive`).
- First-probe-bypass must not reintroduce SYN-storm probe amplification (cap:
  one immediate probe per cold key, then normal throttle).

## 7. Risk
| Class | Level |
|---|---|
| Behavioral regression | MED — touches the cold-connect + warm-pass paths (HA-adjacent) |
| Hot-path perf | LOW — slow-path / control-plane only |
| HA | **MED** — warm-pass gating is cluster-state-coupled; `make test-failover` gating |
| Architectural | LOW — extends #1769/#1771/#1636 mechanisms |

## 8. Test plan
- Unit: resolver first-probe-bypass; warm-pass driver resumes after a simulated
  peer-disconnect/RG-churn.
- **Live repro (the hard part):** overnight-scale idle then a cold connect, with
  the resolver-counter capture (`get_attempts` climbs / `get_resolved` lags =
  resolver-engaged-but-slow → Path B; warmer-last-pass-age large = Path A).
  Captures: `/tmp/idle-hang-longcapture.out` (running) + the operator's overnight
  capture.
- `make test-failover` (warm-pass gating is HA-coupled) — gating.
- Smoke matrix unaffected (slow-path change).

## 9. Out of scope
- #1771 §2.1 per-key epoch (Phase 4, separately gated on `epoch_rejects`).
- #1771 §2.6 counters (separate follow-up) — though a `neighbor_warm_last_pass_age`
  gauge belongs in Path A.

## 10. Open questions for adversarial review
1. **Does the smoking-gun capture show the resolver engaged-but-slow (Path B)
   or the warmer-off-and-aged (Path A) as the dominant factor?** (Gate.)
2. Why did `queue_warm_pass` stall for 17.5h after an 8s peer-disconnect with
   the daemon up — what's the exact gate, and is it the coordinator tick or the
   `skips_when_owning_rg_inactive` RG-state stuck "inactive"?
3. Is first-probe-bypass safe vs SYN-storm probe amplification (one probe/cold
   key)? Does it interact with the per-key pending bound (#1779)?
4. Is the TCP-SYN-backoff-compounding analysis the real "a while," or is there
   a genuine stuck state (resolver spinning, get_attempts climbing without
   resolve)? The capture decides.
5. Is fixing only the warmer (Path A) sufficient, making Path B unnecessary
   churn on the resolver hot-ish path? Or is B needed for the
   warmer-lapses-anyway case?
