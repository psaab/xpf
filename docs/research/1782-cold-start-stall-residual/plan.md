# #1782 — Residual cold-start stall (post-#1780 Path A): capture-first research plan

**Status:** DRAFT v3 — folds r2 (Codex PLAN-NEEDS-MAJOR on H3-timing-signal + Option-B-trigger-point; AGY PLAN-READY incl. Q7 deep-dive; Claude SMR PLAN-READY). Pending r3.

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

This research is **capture-first**. Deliverable: (a) a stall-capture harness +
the small instrumentation (a separate capture-only PR) that makes the next
overnight occurrence conclusive, and (b) a code-grounded causal model with
falsifiable per-mechanism signatures. The root-cause pin and the fix are
**gated on a captured overnight occurrence** and deferred to `/engineer`. If the
capture shows Path A already removed the operator-visible harm, or that the
residual is unavoidable cold-start kernel re-resolution within an acceptable
SLO, **PLAN-KILL (close #1782) is an acceptable outcome.**

## 2. Honest scope/value framing

The win is cold-path latency/correctness, not throughput: once warm, the
dataplane hits line rate (23/22.7 Gb/s in #1781 smoke). The cost is a
few-second stall on the *first* flows after idle — annoying, occasionally
TCP-fatal under aggressive app timeouts, bounded and self-healing. If the
capture shows neighbor resolution completes within an acceptable cold-start SLO
and the residual is pure TCP/app behaviour, **PLAN-KILL is acceptable** (we'd
document the envelope instead). Note (Codex r1): even if TCP RTO dominates, if
the dataplane is *dropping* parallel cold SYNs (H5) or fast-failing retransmits
(H1), that is fixable behaviour, not automatic closure.

## 3. What's already established (rules in/out)

- **Not the loop.** Live gauge node0: resolve 6.1s / force_probe 6.5s /
  clean_failed 1.6s / warm 6.5s — all within cadence. #1780 Path A watchdog
  confirms no phase wedged.
- **2h idle does NOT reproduce** (pre-Path-A capture): at 7200s idle the kernel
  neighbor for .200 was `DELAY` with a valid lladdr, all `neighbor_resolver_*`
  counters 0, cold connect clean at 21.8 Gb/s. Needs *overnight* idle.
- **Dump path accepts DELAY/STALE** (Codex+AGY verified, `neighbor.rs:345`):
  only INCOMPLETE (0x01) + FAILED (0x20) are unusable. So a kernel-`DELAY`
  entry, *if present in `dynamic_neighbors`*, is usable — the miss must come
  from **absence**, not state.
- **Snapshot-regen RULED OUT** (AGY verified): `apply_manager_neighbors`
  (`coordinator/mod.rs:151-204`) updates the map atomically; regen does not
  transiently clear usable state. Dropped from the candidate set.

## 4. Code map (the cold path, end to end)

Per-worker, worker-owned, no cross-core sync (`worker/mod.rs`). The cold path
has **two distinct stages** — getting this wrong was the v2 error (Codex r2):

- **Stage 1 — first MissingNeighbor packet (NOT the resolver).** On a
  `dynamic_neighbors` miss the hot path **triggers kernel ARP/NDP resolution**
  (`trigger_kernel_arp_probe`, `poll_descriptor/mod.rs:2193`) so the kernel
  itself sends the solicitation through the normal stack (which may create/
  advance the kernel INCOMPLETE→… NUD state as a consequence), and buffers
  **one representative packet**
  per `(egress_ifindex, next_hop)` in `pending_neigh` (#1771 §2.2,
  `worker/mod.rs:124-137`); duplicate siblings for the same key are
  **dropped+recycled** (`poll_descriptor/mod.rs:2434` `if
  !pending_neigh.contains_key(key) && len < MAX_PENDING_NEIGH`). The #1769
  shared resolver is **NOT** invoked here. The netlink monitor publishes the
  entry once the kernel resolves it; the buffered packet is replayed and its
  wait is recorded as **`neighbor_pending_dwell`** (#1772,
  `neighbor_dispatch.rs:152`) = `now_ns − queued_ns`. **This dwell is THE
  initial-resolution timing signal**, not the resolver RTT.
- **Stage 2 — neg-cache fast-fail (where the #1769 resolver lives).**
  `neg_neigh_cache` keyed `(egress_ifindex, next_hop)`, `NEG_NEIGH_TTL_NS = 3 s`
  (`mod.rs:363`), is armed by `neg_neigh_record` (`neighbor_dispatch.rs:121`)
  **only when the `pending_neigh` entry times out** in `retry_pending_neigh`
  (`neighbor_dispatch.rs:105`) at `PENDING_NEIGH_TIMEOUT_NS` — **2 s default
  fallback** (`mod.rs:332`), **800 ms fast path** only when
  `compute_pending_neigh_timeout_ns` validates the kernel retrans sysctls
  (`forwarding_build/mod.rs:454`). While active, `neg_neigh_gate`
  (`poll_descriptor/mod.rs:2038`) fast-fails further packets AND **only here**
  routes the key through the #1769 resolver (`poll_descriptor/mod.rs:2100`).
- **Per-key resolver** (#1769, `neighbor_resolver.rs`, Stage-2-only): confirms
  only **REACHABLE/PERMANENT** into `dynamic_neighbors` (`classify_nud:375-393`);
  on STALE/DELAY/PROBE it is **probe-only** (`:700`) — it does NOT reuse the
  kernel's existing usable lladdr. Inserts are epoch/generation-guarded
  (`sharded_neighbor.rs:120 insert_confirmed_if_unchanged`). Its RTT is
  `neighbor_resolver_get_rtt` — which measures the **Stage-2** path, not the
  first-miss resolution.
- **DELNEIGH** removes from `dynamic_neighbors` (`neighbor.rs:359`).

## 5. The causal model (one chain, not independent hypotheses)

r1 (Codex) corrected the v1 ranking. The symptom is a single chain; each link is
separately falsifiable:

- **ROOT — H2: the next-hop is ABSENT from `dynamic_neighbors` after overnight
  idle**, even though the kernel keeps it DELAY-usable. The dump path would
  serve a present DELAY entry with zero stall (§3), so the bug is the *absence*.
  Precise cause is a **missed/unpublished re-add** after a DELNEIGH/GC during
  idle (Codex: "not DELNEIGH alone"). *Signature:* keyed `dynamic_neighbors`
  miss at t0 for an IP the kernel shows DELAY/STALE-usable; a DELNEIGH/GC for it
  in the timestamped idle-window `ip monitor neigh` log.
- **WHY SLOW — H3: resolution waits for the kernel REACHABLE transition instead
  of reusing the kernel's already-usable DELAY/STALE lladdr.** On the first miss
  (Stage 1) the hot path triggers kernel ARP/NDP resolution and waits for the
  kernel ARP/NDP→REACHABLE round-trip + netlink publish before `dynamic_neighbors` is
  populated, even though the kernel often already holds a usable DELAY/STALE
  lladdr it could forward on. That round-trip is the core latency. (If Stage 2
  is reached, the #1769 resolver also refuses DELAY/STALE — `:700` probe-only —
  compounding it.) *Signature:* kernel DELAY/STALE-usable at t0;
  `dynamic_neighbors` populated only after the REACHABLE transition; the latency
  is measured by **`neighbor_pending_dwell`** (Stage-1 buffered-packet wait),
  NOT `neighbor_resolver_get_rtt` (which only covers the Stage-2 resolver path).
- **WHY MULTI-FLOW — H5 (new, Codex): one-representative `pending_neigh` per
  `(worker, next_hop)` drops sibling cold SYNs.** Parallel cold flows to the
  same next-hop on the same worker: ONE SYN is buffered (drives the probe), the
  SIBLINGS are recycled/dropped (`poll_descriptor/mod.rs:2435`) → they wait for
  TCP SYN RTO. This explains "multiple flows stall together, then recover" with
  **zero** neg-cache fast-fails. *Signature:* a pending-duplicate-drop counter
  climbs at t0 while `neg_neigh_fast_fail` stays low; pcap shows sibling SYN
  retransmits while one flow connects promptly.
- **AMPLIFIER — H1: per-worker 3 s neg lockout**, armed only after the pending
  timeout (**2 s default / 800 ms validated-sysctl fast path**), fast-fails
  further packets (resolver nudged in Stage 2). NOTE (Codex): the cache is
  **per-binding/per-worker**, not one global entry — flows on different RSS
  queues/bindings each arm their own; common recovery is via the shared
  `dynamic_neighbors`. *Signature:* `neg_neigh_fast_fail` climbs after the
  pending timeout; lockout clears on the REACHABLE re-add, not at the 3 s TTL.
- **AMPLIFIER — H4: TCP SYN-RTO.** The first SYN is *buffered* (H5), not
  dropped, so RTO only fires for (a) the buffered SYN if resolution exceeds the
  pending timeout (2 s default / 800 ms fast path), or (b) the dropped sibling
  SYNs (H5) immediately. Linux RTO ~1 s, 2 s. *Signature:* pcap SYN-retransmit
  pattern; resolution timestamp vs the SYN that succeeds.

Net wall-clock ≈ **first-miss resolution dwell (H3, `neighbor_pending_dwell`)**
+ **sibling SYN-RTO (H5)**, with H1 a secondary amplifier only once the pending
timeout (2 s / 800 ms) is crossed. The capture measures the split.

## 6. The capture harness (first deliverable)

`test/incus/capture-cold-stall.sh` (research-branch only). Run at the next
overnight idle; record a **pre-connect t0′ sample** (just before the cold
connect, while still idle — Codex r2: needed to separate H2 from H3) plus
per-flow at t0 (stall start) / t1 (recovery):

1. per-flow connect→first-byte wall time;
2. **keyed** `dynamic_neighbors contains(ifindex, ip)` at **t0′ (pre-connect)**
   and t0 (see §7 — needs the query) + `ip neigh` NUD state/lladdr at t0′/t0/t1.
   A miss at t0′ with the kernel showing DELAY/STALE-usable is the H2 fingerprint
   (absence pre-existed the connect, not caused by it);
3. counter deltas t0→t1: **`neighbor_pending_dwell_*`** (the Stage-1 H3 signal,
   #1772), `neighbor_pending_timeout_drops_total`, **per-worker
   `neg_neigh_fast_fail`** and **pending-duplicate-drop** counters (§7),
   `neighbor_resolver_{get_attempts,get_resolved,probe_on_stale,epoch_rejects,get_rtt_*}_total`
   (Stage-2 only — nonzero ⇒ the neg-fast-fail path was reached),
   `neighbor_warm_*`;
4. **timestamped `ip monitor neigh` started BEFORE the idle window** (Codex —
   otherwise H2 is guesswork): catches the DELNEIGH/GC that removes the entry;
5. `tcpdump` of the SYN exchange for the connecting flow AND a sibling
   (measures H5/H4 SYN-RTO contribution);
6. the actual `pending_neigh` timeout / retrans-sysctl state (2 s vs 800 ms —
   §4) so the H1-arming threshold is known;
7. the Path-A `{phase}` gauge at t0 (regression guard — must be healthy).

Per-mechanism column mapping so one capture is conclusive: **H2**←(2) t0′ miss +
(4) DELNEIGH; **H3**←`neighbor_pending_dwell` ≈ stall + DELAY→REACHABLE
transition timing (NOT get_rtt); **H5**←dup-drop counter + sibling pcap;
**H1**←`neg_fast_fail` nonzero (only if dwell > the §6.6 timeout); **H4**←pcap.

## 7. Instrumentation gaps → capture-instrumentation PR-1 (small, observability-only)

The harness depends on code that must merge first. This is an explicit
**two-PR sequence**:

- **PR-1 (capture-only `/engineer`, mergeable on its own):**
  - Expose **`xpf_userspace_neg_neigh_fast_fail_total`** (today debug-only,
    `types/runtime.rs:261` aggregated in `worker/loop_body/mod.rs:789`),
    per-worker if cheap.
  - Expose a **pending-duplicate-drop counter** at the H5 sibling-drop site
    (`poll_descriptor/mod.rs:2434`). It must count the **`contains_key`
    duplicate** case *specifically* — NOT the co-located `len >=
    MAX_PENDING_NEIGH` capacity-drop case, which is a different condition (Codex
    r2). Per-worker, so RSS-fan-out (Q5) is separable from true H5. Without it,
    H5 vs H1 is indistinguishable.
  - Extend **`dynamic_neighbor_status`** (`coordinator/status.rs:12`, today
    returns `(len, generation)`) with a **keyed `contains(ifindex, ip)`** query
    (gRPC debug RPC or targeted surface) so the harness can confirm the t0 miss.
- **Operator runs one overnight capture with PR-1 live.**
- **PR-2 (`/engineer`):** the fix, Path-Option chosen by the capture.

The `/research` deliverable is the harness script + the PR-1 spec + this
hypothesis/signature table — NOT a runnable end-to-end capture today.

## 8. Hidden invariants any eventual fix must preserve

- **#1651** neg cache stops a SYN-flood-to-dead-host from each packet
  consuming a buffer/probe. A fix shortening/skipping it must not re-open that
  (the Option A trap).
- **#1771 §2.2** one-representative `pending_neigh` pins ≤1 UMEM frame per dead
  host. An H5 "fix" that buffers more siblings re-opens that frame-pinning
  amplification — avoid unless H3-fix proves insufficient.
- **#1769** resolver inserts are epoch/generation-guarded; an Option B
  DELAY-reuse insert MUST go through `insert_confirmed_if_unchanged`
  (`sharded_neighbor.rs:120`) or it can resurrect a MAC the monitor just
  removed (Codex). **Necessary but not sufficient** (Codex r2) — see Q7 below.
- **Q7 — DELAY/STALE-reuse semantics is a FIX-GATING decision, not a footnote**
  (Codex r2). Reusing a DELAY/STALE kernel lladdr relaxes #1769's deliberate
  REACHABLE-only rule. AGY r2 deep-dive (to be ratified at PR-2): because the
  AF_XDP datapath bypasses the kernel TCP stack, a DELAY entry never gets
  `dst_confirm`, so the kernel still runs its own DELAY→PROBE cycle
  (`delay_probe_time`, ~5 s) and, on a silent MAC change during idle (VM
  migration / failover without GARP), userspace would transiently TX to a stale
  MAC — but it **self-heals**: the kernel's unicast probe fails → falls back to
  multicast → the host's reply drives a REACHABLE netlink update → the monitor
  corrects `dynamic_neighbors`. AGY's verdict: a bounded transient wrong-MAC
  window is an acceptable trade vs a guaranteed multi-second cold-start stall.
  PR-2 must ratify this explicitly.
- **Hot-path non-blocking (AGY r3, hard):** anything the Option-B first-miss
  path does on the poll thread MUST be non-blocking — no synchronous netlink
  (`RTM_GETNEIGH`) send/recv, no lock that the monitor thread can hold across a
  syscall. A blocking transaction in the poll loop stalls the whole RSS ring
  (ms-scale) and collapses warm-flow throughput. Use a lockless local mirror
  fed by the async netlink monitor.
- **HA:** cold path runs on both nodes; `make test-failover` (13/0 on Path A)
  must stay green.

## 9. Path Options for the EVENTUAL fix (capture picks; NOT chosen here)

- **Option B (leading) — reuse a DELAY/STALE-usable kernel lladdr at the
  FIRST-miss site.** CRITICAL framing correction (Codex r2): the first miss is
  Stage 1 (trigger kernel ARP probe + buffer), and the #1769 resolver is Stage-2-only
  — so modifying *only the resolver* would NOT touch the first miss. B must add
  an **early first-miss path**: on a `dynamic_neighbors` miss, before inserting
  the kernel ARP probe and buffering, check a **non-blocking local userspace mirror** of
  the kernel neighbor table (populated asynchronously by the netlink monitor
  thread) for a usable (DELAY/STALE) lladdr and confirm it into
  `dynamic_neighbors` via `insert_confirmed_if_unchanged`, forwarding
  immediately. **HARD CONSTRAINT (AGY r3): the first-miss check MUST be
  strictly non-blocking — NO synchronous `RTM_GETNEIGH`/netlink transaction on
  the poll thread.** A blocking netlink send+recv in the poll loop freezes the
  worker core for milliseconds during a miss, dropping packets and collapsing
  throughput on every warm flow sharing that RSS ring. Read a lockless local
  mirror, never issue a blocking syscall. This attacks H3 at Stage 1 and
  **shrinks the H5/H1/H4 window** — but does **not** fully eliminate H5:
  same-poll-burst siblings can still be dropped before the confirm propagates,
  so PR-2 must state whether the first-miss reuse populates the map
  inline-synchronously within the poll batch or asynchronously. Subject to the
  Q7 semantic ratification + the #1769 epoch guard (§8).
- **Option D (compound with B) — don't keep the neg entry armed while a probe
  is progressing / when the kernel has a usable lladdr.** Narrow H1 mitigation
  that preserves the dead-host defense (only suppresses the false lockout when
  resolution is genuinely advancing).
- **Option C — keep data-path-active next-hops warm during idle** (attacks H2 at
  the source so they never go absent). Broader blast radius; interacts with
  `warmNeighborCache` scoping. Candidate if H2's re-add gap is structural.
- **Option A — shorten/skip the 3 s neg TTL for direct hosts.** Re-opens #1651
  (§8). Likely wrong on its own.
- **H5-direct (multi-pending / sibling-replay) — avoid** unless B is
  insufficient; conflicts with #1771 §2.2 (§8).

**Lean (capture to confirm): B (first-miss reuse) + D.** B at the Stage-1
first-miss site shrinks the vulnerable window so the H5/H1/H4 amplifiers rarely
engage; D removes the residual false lockout. If the capture shows H2's absence
is structural (the re-add is never published), **C** moves up — keeping the
entry warm so it never goes absent is then more robust than reusing it on miss.
The capture's t0′ (pre-connect) `dynamic_neighbors` sample + the `ip monitor`
DELNEIGH log decide B-vs-C.

## 10. Out of scope (explicitly)

- The fix (PR-2; capture-gated).
- `regenDebouncer` hardening and `warmNeighborCache` UDP-flood scoping —
  separate sub-follow-ups on #1782.
- Throughput/fairness (orthogonal).

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. Is the H3+H5 split the dominant wall-clock contributor, or does H4 (TCP RTO)
   dominate such that only TCP-tuning helps (→ document-the-envelope)?
2. Does PR-1's instrumentation (per-worker neg fast-fail + pending-dup-drop +
   keyed `contains`) actually separate H5 from H1, and H2 from H3?
3. Is a keyed `contains(ifindex,ip)` debug query the right surface, or should
   PR-1 instead snapshot the per-worker `dynamic_neighbors`/`neg`/`pending` key
   sets at t0?
4. Is the residual worth fixing vs accepting a cold-start SLO (→ PLAN-KILL)?
5. Could "multiple flows together" be a per-worker/RSS-queue artifact (all cold
   flows hashing to one worker) rather than H5? Does the per-worker counter
   split tell us?
6. Does `forceProbeNeighbors`/the warm set even target directly-connected
   data-path hosts like .200, or only configured next-hops (bears on Option C)?
7. **[Answered r2, ratify at PR-2]** Is Option B's DELAY-reuse semantically
   safe? AGY r2 deep-dive (§8): the kernel self-heals a transient stale-MAC via
   its own DELAY→PROBE cycle + netlink REACHABLE update; bounded wrong-MAC
   window is an acceptable trade vs a guaranteed multi-second stall. PR-2 must
   ratify this as the explicit fix-gating decision.
8. **[r2]** Does the first-miss reuse (Option B) need to be inline-synchronous
   within the poll batch to stop same-poll-burst sibling drops (H5), or is an
   async confirm enough? The sibling pcap + dup-drop counter answer this.
