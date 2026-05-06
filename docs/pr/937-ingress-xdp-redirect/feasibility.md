---
status: DRAFT v1 — feasibility doc for #937 / Codex Path 1; pending adversarial review + verification test
issue: #937
phase: feasibility-only — NO implementation. Verification test required before any plan or code.
prerequisites:
  - #1206 (CoSQueueRuntime split) merged
  - Codex CoS findings (/tmp/codex-cos.md) endorses this as Path 1, but flags open questions about XSKMAP behavior
  - User mandate: drive per-5-tuple fairness end-to-end through proper review discipline
---

## 1. The hypothesis (#937 / Codex Path 1)

> Redirect packets at ingress XDP **before** AF_XDP UMEM ownership is
> locked, using a flow_key→worker BPF map. RSS skew can be corrected
> at the XDP layer without per-tuple HW state.

If feasible, this is the only known mechanism that solves cross-worker
fairness while preserving aggregate throughput (the user explicitly
accepts aggregate regression, but path 1 doesn't require that
trade-off).

## 2. The blocker discovered in current code

`userspace-xdp/src/lib.rs:1305-1312` (existing code, not a hypothesis):

> AF_XDP delivery is queue-bound. XDP may only redirect to a socket
> bound to the packet's actual RX queue. Hashing to a different
> userspace queue here silently strands packets between redirect
> intent and ring delivery.

`select_userspace_queue()` returns `rx_queue_index % queue_count` —
the queue is **forced** to match the inbound RX queue because of
this kernel constraint.

This is the standard AF_XDP `XSK_BIND` semantics: each XSK socket is
bound at registration time to a specific `(ifindex, queue_id)` pair.
`bpf_xdp_redirect_map(XSKMAP, slot)` only delivers if the slot's
socket's bound queue matches the packet's current RX queue. Otherwise
the kernel silently drops the packet (no error path; no counter).

Per the codebase comment, this was empirically validated. It is the
fundamental architectural reason the `cross-binding rewrite` was
declared "impossible" at `docs/userspace-jit-design.md:442-448`.

## 3. Three structural alternatives (each with its own cost)

### Option A: Verify the constraint still holds on kernel 7.0.0-rc7+

The test cluster runs kernel `7.0.0-rc7+` (very recent). Earlier
kernels enforced the queue-locking restriction strictly, but it's
possible (not confirmed) that newer kernels relax this for some
XSKMAP variants or per-binding-flag combinations.

**Verification test** (described in §6):
- Set up a minimal XDP program on a multi-queue interface
- Bind two XSK sockets, one each on RX queues 0 and 1
- From XDP running on queue 0, `bpf_xdp_redirect_map(XSKMAP, slot=1)`
- Send packets that RSS-hash to queue 0
- Observe whether they appear on socket-1's RX ring or are dropped

If verified-works → Option D (extension of current architecture, no
need for cpumap hop or N² sockets).

If verified-still-stranded → Options B / C / pivot to Path 2.

### Option B: cpumap redistribution

Standard kernel-supported pattern for cross-CPU work redistribution:

1. XDP program at ingress consults flow_key → target_cpu map
2. `bpf_xdp_redirect_map(CPUMAP, target_cpu)`
3. cpumap-target XDP program runs on target_cpu, then redirects to
   the AF_XDP socket bound to that CPU's RX queue (now matches —
   target_cpu's queue is what packets arrive on after cpumap)

Cost:
- Extra cpumap hop per redirected packet (~100 ns measured in
  upstream selftests)
- Per-packet ringbuf push/pop on cpumap target queue
- Cache-line bounce: source CPU writes the cpumap entry, target CPU
  reads
- Higher latency for redirected flows (one extra hop) — fine for
  bulk TCP, may matter for mouse latency

Total estimated overhead: ~200-300 ns per redirected packet.
At 25 Gb/s line rate (480 ns budget), that's 40-60% of budget.
Acceptable IF redirect targets only a fraction of packets (e.g.,
new-flow SYN classification only, or 1-in-N sampling).

### Option C: per-(worker, queue) socket binding (N² sockets)

Each worker binds an AF_XDP socket on **every** RX queue, not just
its own. So if there are 6 workers and 6 RX queues, we have 36
sockets total.

XDP can then redirect to any (worker, queue) pair, because the
target socket is bound to the current queue.

Cost:
- 36 UMEMs vs 6 (6× memory): ~96 MB × 6 = ~576 MB UMEM total
  on the firewall (current is 96 MB × 6 = 576 MB; same since each
  worker's UMEM doesn't grow)
- Wait, actually each (worker, queue) socket needs its OWN UMEM
  because UMEM is per-socket. 36 UMEMs × 16 MB ≈ 576 MB. Vs current
  96 MB × 6 = 576 MB. Same total memory.
- Actually probably worse: each worker now has 6 sockets to poll,
  not 1. CPU cycles split 6 ways across the worker's sockets.
- Worker selection logic gets more complex: which of my 6 sockets
  do I poll first? Round-robin? Hashed?

This is effectively re-doing AF_XDP queue ownership. Lots of work,
unclear win.

### Option D: extension if Option A verifies (cleanest)

If kernel 7.0.0-rc7+ relaxes the queue-binding restriction:
- Add a flow_key → target_slot BPF hash map
- XDP program: parse 5-tuple, look up override, use override OR
  default `rx_queue_index % queue_count`
- `select_userspace_queue` becomes:
  ```rust
  if let Some(target) = FLOW_OVERRIDE_MAP.get(&flow_key) {
      *target
  } else {
      rx_queue_index % queue_count
  }
  ```
- Userspace controller: detects RSS-skew via per-binding flow
  count + per-binding bytes, installs overrides for new flows
  toward under-loaded workers (power-of-two-choices)

**Per-packet cost**: 1 hash map lookup (~20-50 ns) + 1 comparison.
Well within budget.

This is what Codex's Path 1 envisions. It's only viable if Option
A verifies.

## 4. Decision tree

```
Verification test (§6) on kernel 7.0.0-rc7+:
├── PASS (XSKMAP cross-queue works) → Option D, plan the impl
├── FAIL (still stranded) → Option B (cpumap) cost-benefit decision
│   ├── overhead ≤ ~150 ns per redirect AND only redirected on
│   │   new-flow SYN → proceed Option B
│   └── overhead > 150 ns OR redirect on every packet → reject;
│       pivot to Path 2 (AFD/CSFQ ECN overlay, #1211)
└── INDETERMINATE (e.g., delivers but cwnd stalls) → reject; pivot
```

## 5. Why this matters for the user mandate

Per-5-tuple fairness across RSS-skewed worker placement requires one
of:

1. **Re-route packets across workers** — Path 1 (#937), this doc.
   ONLY works if Option A or B clears the verification gate.
2. **Backpressure via ECN** — Path 2 (#1211). Sidesteps the queue-
   binding constraint entirely. Requires TCP sender response.
3. **Workload-aware product gate** — Path 4. Accepts the structural
   limit; document the regime.

We tried local stall (#1215). It's dead. We tried RSS rebalance
(#840). Reverted. We tried n-tuple steering (#1203). Closed.

Path 1 is the next thing to try. If it doesn't pass §6, Path 2 is the
backup; #1211 needs its own race-safety re-design from #838's killed
v1.

## 6. Verification test — minimum viable feasibility prototype

**Goal**: empirically confirm whether `bpf_xdp_redirect_map(XSKMAP,
slot)` delivers across (queue_a → queue_b) or silently strands on
kernel 7.0.0-rc7+ with current i40e and virtio drivers.

### 6.1 Test setup

On `loss:xpf-userspace-fw0`:

1. Create a minimal multi-queue interface scenario. The PF
   passthrough (`enp9s0f0np0` → `ge-0-0-3`) has multiple RX queues
   (verify with `ethtool -l ge-0-0-3`).
2. Detach xpfd's XDP program temporarily (or add a feature flag).
3. Load a tiny verification XDP program that:
   - Parses ethernet + IP
   - For TCP packets to a specific dst port, redirects via XSKMAP
     to a slot bound to a DIFFERENT RX queue
   - Else passes
4. From userspace, bind two AF_XDP sockets:
   - Socket A on (ge-0-0-3, queue 0) at slot 0
   - Socket B on (ge-0-0-3, queue 1) at slot 1
5. Generate traffic from `loss:cluster-userspace-host` such that
   RSS hashes packets to queue 0.
6. Observe: do packets appear on Socket B's RX ring (PASS), or are
   they dropped silently (FAIL)?

### 6.2 Measurement

- Per-socket counters: read via `getsockopt(XDP_STATISTICS)` to see
  rx_dropped vs rx_invalid_descs vs frames-actually-received
- XDP fallback counters: existing `incr_fallback_stat` mechanism in
  the codebase already records these
- iperf3 single-stream from host: if packets go through, throughput
  is non-zero on Socket B; if stranded, throughput is zero (loss is
  100%)

### 6.3 Acceptance for proceeding to plan

| Outcome | Next step |
|---|---|
| Cross-queue XSKMAP redirect delivers reliably | Draft Option D plan |
| Stranded silently | Quantify Option B (cpumap) overhead in a 2nd verification |
| Delivers but with cwnd stall (e.g., reorders) | Treat as failure; pivot Path 2 |

### 6.4 Time budget

- 1 day setup + verification test
- 1 day Option B cpumap measurement (if needed)
- Result: feasibility verdict before any plan v1

## 7. Test fixture deficit (Codex's Path 0)

**Independently of the feasibility outcome**, we cannot evaluate
fairness changes without a deterministic RSS-skew fixture. Codex's
recommended execution order step 1 is "build a deterministic RSS-skew
fixture". Without that:

- Today's 47% per-flow CoV measurement was a single point.
- Cannot reproducibly produce 1+3, 0/2/2/2/3/3, balanced 2/2/2/2/2/2,
  P=128 uniform distributions.
- Any CoV improvement / regression measurement is noisy.

§6 is the feasibility test. **Step 0** is the measurement infra. Both
need to happen before any implementation. They are independent and
can run in parallel.

## 8. Out of scope for this feasibility doc

- Implementation plan (Option D plan, if §6 passes) — separate doc.
- Userspace control-plane logic (when to install overrides, which
  worker to target, hysteresis to avoid flapping) — separate doc.
- Reverse-path symmetry — separate concern; needs explicit handling
  if redirect changes which worker owns the flow.
- Session migration if redirect happens mid-flow — initial Option D
  scope is **new-flow only** (TCP SYN classified) per Codex's
  recommendation.
- AFD/CSFQ ECN overlay — Path 2; complementary, separate effort.

## 9. Open questions for adversarial review

1. **Is the §2 constraint actually still binding on kernel
   7.0.0-rc7+?** This is the central question. The answer determines
   whether Option D or Option B is the path.

2. **Is Option B's ~200-300 ns overhead acceptable on the redirect
   path?** At 25 Gb/s line rate, 480 ns budget. 50% used by cpumap
   hop. If we redirect only on new-flow SYN (rare event), the
   amortized cost is small. But if redirect happens per-packet, it's
   too expensive.

3. **What's the right Option B redirect granularity?** Per-flow
   (install override on first SYN, all subsequent packets follow
   override) vs per-packet (look up every packet, no install)?
   Per-flow is cheaper but requires session-table state at the BPF
   layer.

4. **Reverse path**: when we redirect outbound packets to worker B,
   the RTT response packet still gets RSS-hashed to whichever worker
   the kernel picks. If we want symmetric per-flow worker
   assignment, we need to redirect inbound RTT packets too, which
   means the override map is keyed differently (per-direction or
   bidirectional 5-tuple).

5. **Userspace control plane churn**: how often does the override
   map update? If too frequent, overhead. If too slow, stale.
   Power-of-two-choices over per-binding load? Pure round-robin?

6. **Mid-session migration**: if we change a flow's owner while it's
   active, session state on the old worker is orphaned. Initial
   scope is new-flow-only, but if we restart the daemon mid-session,
   what happens?

7. **Is Path 2 (AFD/CSFQ) actually a viable backup if Path 1
   fails?** #838-AFD-lite was killed for race surfaces. A fresh
   Path 2 design needs its own race-safety analysis. Is the user
   prepared to do that work?

## 10. Verdict request

Reviewers: please answer §9 Q1 specifically (the §2 constraint on
current kernel). The rest of this doc is contingent on that.

PLAN-READY → execute §6 verification test, report result, then plan.
PLAN-NEEDS-MINOR → tighten test methodology / scope.
PLAN-NEEDS-MAJOR → restructure (e.g., evaluate Option B in
parallel with Option A; or argue we should pivot to Path 2 first
before spending §6 effort).
PLAN-KILL → §2 constraint is well-known kernel behavior that won't
relax on 7.0.0-rc7+; cpumap overhead is unacceptable for production;
no path 1 variant clears the gate. Pivot to Path 2 or Path 4.
