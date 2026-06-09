# #1782 — Residual cold-start stall (post-#1780 Path A): capture-first research plan

**Status:** DRAFT v1 — pending 3-way hostile plan review (Codex + AGY + Claude SMR)

## 1. Issue framing

#1780 Path A (PR #1781, merged `a531b6687`) stall-hardened the Go periodic
neighbor loop so it can no longer freeze — the multi-hour overnight hang is
gone. The operator re-tested on the Path-A build and reports a **residual,
narrower symptom**:

> "I waited, it was kinda fixed, but we lagged on multiple flows hanging or not
> performing for a few seconds. Finally after a few seconds it was running at
> full speed. There's still a bug."

So: after long (overnight) idle, the **first flows to a data-path next-hop
stall / underperform for a few seconds — multiple flows together — then snap to
full speed.** This is a per-connect *cold-start tax*, not a loop freeze.

This research is **capture-first**. Its deliverable is (a) a stall-capture
harness + the small instrumentation needed to make the next overnight
occurrence conclusive, and (b) a ranked set of falsifiable mechanism
hypotheses with their capture signatures. The actual root-cause pin and the
fix are explicitly **gated on a captured overnight occurrence** and deferred to
`/engineer`. If the capture shows Path A already removed the operator-visible
harm, PLAN-KILL (close #1782) is an acceptable outcome.

## 2. Honest scope/value framing

The win is correctness/latency on the cold path, not throughput: once warm, the
dataplane already hits line rate (23/22.7 Gb/s in #1781 smoke). The cost is a
few-second stall on the *first* flows after idle — annoying, occasionally
TCP-fatal under aggressive app timeouts, but bounded and self-healing. If
reviewers conclude the residual is within acceptable cold-start behaviour for a
firewall (kernel ARP/ND re-resolution is inherently not free), **PLAN-KILL is
an acceptable verdict** — we would instead just document the expected cold-start
latency envelope.

## 3. What's already established (rules in/out)

- **Not the loop.** Live gauge on node0 post-deploy: resolve 6.1s / force_probe
  6.5s / clean_failed 1.6s / warm 6.5s — all within cadence. The #1780 Path A
  watchdog confirms no phase is wedged. The residual is downstream of the loop.
- **2h idle does NOT reproduce** (pre-Path-A capture, `idle-hang-longcapture.out`):
  at 7200s idle the kernel neighbor for .200 was `DELAY` with a valid lladdr,
  all `neighbor_resolver_*` counters 0, cold connect clean at 21.8 Gb/s. The
  symptom needs *overnight* idle (8–12h+).
- **The naive "userspace REACHABLE-only miss" hypothesis is WEAKENED.** The dump
  path `userspace-dp/src/afxdp/neighbor.rs:346-351` treats only INCOMPLETE
  (0x01) + FAILED (0x20) as unusable; STALE/DELAY/PROBE/PERMANENT/NOARP are all
  accepted into `dynamic_neighbors`. So a plain kernel-`DELAY` entry, if present
  in the userspace map, would be usable — a simple STALE/DELAY state does not by
  itself explain a miss.

## 4. Code map (what the cold path actually does)

- **Negative cache (#1651):** `neg_neigh.rs` + `mod.rs:356-369`.
  `NEG_NEIGH_TTL_NS = 3 s`, `MAX_NEG_NEIGH_CACHE = 256`, keyed `(ifindex,
  IpAddr)`. On a cold packet with no usable neighbor, `neighbor_dispatch.rs:118`
  calls `neg_neigh_record` (arms a 3 s entry); `poll_descriptor/mod.rs:2038`
  runs `neg_neigh_gate` which **fast-fails** (recycles the frame, no
  buffer/probe) for any packet to that key while the entry is active, *unless*
  the resolved-wins closure sees the neighbor now present. The shared monitor
  evicts the entry on RTM_NEWNEIGH.
- **Per-key resolver (#1769):** `neighbor_resolver.rs`. Epoch-guarded,
  **REACHABLE/PERMANENT-only** confirmation into `dynamic_neighbors`; probes on
  STALE/DELAY; revokes on authoritative FAILED. Note: it does **not** confirm a
  DELAY/STALE read into the map — it probes and waits for REACHABLE.
- **DELNEIGH/GC eviction:** `neighbor.rs:289 remove_dynamic_neighbor`, called on
  RTM_DELNEIGH (msgtype 29) and on FAILED/INCOMPLETE parse. A DELNEIGH during
  idle removes the next-hop from `dynamic_neighbors` even though the kernel may
  immediately re-add it in STALE/DELAY.
- **Snapshot regen:** `daemon_neighbor_listener.go:99 regenDebouncer`,
  coalesces RTM_* bursts before regenerating the published snapshot.

## 5. Candidate mechanisms — falsifiable hypotheses (ranked)

These are **not mutually exclusive**; the likely reality is a compound
(H2 eviction → H1 lockout → H4 backoff, with H3 explaining why the resolver
can't shortcut). The capture's job is to identify the **dominant amplifier** of
the few-second wall-clock.

- **H1 (prime) — 3 s negative-cache lockout.** After idle, the first cold
  packet finds `dynamic_neighbors` empty for the next-hop → `neg_neigh_record`
  arms a 3 s entry → **all** flows to that `(ifindex,ip)` fast-fail for up to
  3 s (this is exactly why "multiple flows" stall *together* and recover
  *together*) → resolver probes → REACHABLE → RTM_NEWNEIGH evicts the entry →
  all flows proceed. *Signature:* at stall, the neg-cache holds the key and
  `neg_neigh_fast_fail` climbs; recovery coincides with an RTM_NEWNEIGH
  (REACHABLE) + neg evict; stall ≈ probe RTT, capped at ~3 s.
- **H2 — DELNEIGH/GC evicted the next-hop from `dynamic_neighbors` during
  idle.** Explains *why* the cold miss happens at all given the dump path
  accepts DELAY. *Signature:* a DELNEIGH (or GC-driven remove) for the next-hop
  during the idle window; `dynamic_neighbors` miss for an IP the kernel still
  shows DELAY/STALE.
- **H3 — resolver REACHABLE-only confirmation can't reuse a DELAY-usable kernel
  entry.** The kernel already has the lladdr (DELAY), but #1769 probes and waits
  for REACHABLE rather than confirming the existing MAC, so the stall is the
  full DELAY→PROBE→REACHABLE round-trip. *Signature:* kernel DELAY-usable at
  stall start; `dynamic_neighbors` populated only after the REACHABLE
  transition; `neighbor_resolver_get_rtt` ≈ stall duration.
- **H4 — TCP SYN-retransmit backoff dominates wall-clock.** Even a sub-second
  unresolved window drops the first SYN; Linux retransmits at ~1 s, 2 s, so a
  300 ms resolution gap still reads as ~1 s+ of stall. *Signature:* pcap shows
  SYN retransmits; resolution completes well before the SYN that succeeds.

## 6. The capture harness (first deliverable)

A script (`test/incus/capture-cold-stall.sh`, research-branch only until
`/engineer`) the operator runs at the next overnight idle. On a cold connect it
records, per flow and at stall-start (t0) / recovery (t1):

1. per-flow connect→first-byte wall time (the measured quantity);
2. `ip neigh` NUD state + lladdr for the next-hop at t0 and t1;
3. counter deltas across t0→t1:
   `neighbor_resolver_{get_attempts,get_resolved,probe_on_stale,epoch_rejects,get_rtt_*}_total`,
   `neighbor_pending_timeout_drops_total`, **`neg_neigh_fast_fail_total`** (see
   §7 — must be exposed), `neighbor_warm_*`;
4. `dynamic_neighbors` membership for the key at t0 (see §7 — needs a query);
5. `ip monitor neigh` log across the idle window (catches DELNEIGH/GC = H2);
6. a `tcpdump` of the SYN exchange (measures H4's SYN-retransmit contribution);
7. the Path-A `{phase}` gauge at t0 (must be healthy — regression guard).

Each hypothesis maps to a column so one capture is conclusive.

## 7. Instrumentation gaps the plan must close (small, capture-only)

These are the only code touches in scope, and only at `/engineer` time:

- **Expose `neg_neigh_fast_fail` as a Prometheus counter.** Today it is a
  debug-only accumulator (`types/runtime.rs:261 dbg.neg_neigh_fast_fail`,
  summed in `worker/loop_body/mod.rs`) gated behind debug-log. Promote it to a
  real `xpf_userspace_neg_neigh_fast_fail_total` so the harness can read it
  without a debug build. *Without this we cannot distinguish H1 from H3/H4.*
- **A `dynamic_neighbors` membership probe.** No query path exists today. Add a
  minimal count/contains debug surface (gRPC debug RPC or a metrics gauge of
  `dynamic_neighbors` len per ifindex) so the harness can confirm the t0 miss.
  Lower priority than the fast-fail counter (the neg-cache key set + RTM monitor
  can infer membership), but it removes ambiguity.

## 8. Hidden invariants any eventual fix must preserve

- The #1651 negative cache exists to stop a **SYN-flood to a dead host** from
  each consuming a buffer/probe; any fix that shortens/skips it must NOT
  re-open that amplification (this is the trap in Path-Option A below).
- The #1769 resolver's REACHABLE/PERMANENT-only confirmation is race-safe by
  epoch; any fix that confirms a DELAY read must not resurrect a MAC the monitor
  just removed (the exact race #1769 closed).
- HA: the cold path runs on both nodes; a fix must not change failover neighbor
  behaviour (Path A's `make test-failover` 13/0 must stay green).

## 9. Multiple Path Options for the EVENTUAL fix (surfaced for judgment; NOT chosen here)

Listed so the operator sees the tradeoff space; **the capture picks among
them.**

- **Option A — shorten/skip the 3 s neg-cache TTL for directly-connected
  hosts.** Simplest, directly attacks H1. **Risk: re-opens the #1651 SYN-flood
  amplification** the cache was added to prevent. Likely wrong on its own.
- **Option B (most surgical if H3 confirmed) — confirm a DELAY/STALE-usable
  kernel entry into `dynamic_neighbors` from the resolver's GET read**, instead
  of waiting for REACHABLE. Uses the lladdr the kernel already has → kills the
  cold miss at the source without touching the neg cache. Must respect the
  epoch race (§8).
- **Option C — keep data-path-active next-hops warm during idle** so they never
  degrade to the miss state (extend the warm set / refresh recently-active
  next-hops). Attacks H2. Broader blast radius; interacts with
  warmNeighborCache scoping.
- **Option D — don't arm the neg cache while a probe is in flight or when the
  kernel has a usable lladdr.** Narrow H1 mitigation that preserves the
  dead-host protection (only suppresses the false lockout when resolution is
  genuinely progressing).

Preliminary lean (to be confirmed by capture): **B + D** — B removes the miss
when the kernel already has the MAC; D prevents the 3 s lockout from
overstaying a live resolution — without re-opening #1651. But this is a
hypothesis, not a decision.

## 10. Out of scope (explicitly)

- The fix itself (capture-gated; a separate `/engineer #1782` after a captured
  overnight occurrence picks the Path Option).
- `regenDebouncer` hardening and `warmNeighborCache` UDP-flood scoping —
  separate sub-follow-ups noted on #1782.
- Any throughput/fairness work (orthogonal).

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. Is H1 (3 s neg lockout) really the dominant amplifier, or does H4 (SYN
   backoff) make the neg-cache TTL irrelevant (i.e., even a 0 ms neg cache
   leaves ~1 s of SYN-retransmit stall)? If H4 dominates, no neighbor-side fix
   helps and this is PLAN-KILL / document-the-envelope.
2. Does the capture harness actually disambiguate the four hypotheses, or do two
   of them produce identical signatures (e.g., can we distinguish H2-eviction
   from H3-resolver-wait without a `dynamic_neighbors` query)?
3. Is exposing `neg_neigh_fast_fail` as a counter sufficient, or do we need
   per-key arm/evict timestamps to measure lockout duration precisely?
4. Is the residual even worth fixing, or is a few-second cold-start after
   overnight idle acceptable firewall behaviour (PLAN-KILL → document)?
5. Could the "multiple flows together" be something other than a shared
   `(ifindex,ip)` neg entry — e.g., a single RSS-queue/worker stall, or the
   snapshot-regen briefly clearing state for all flows? Does the harness
   capture enough to tell?
6. Is there a risk that the *next-hop* (gateway) is fine but it's the **direct
   host** .200 that degrades — and does the warm set / forceProbe even target
   directly-connected data-path hosts, or only configured next-hops?
