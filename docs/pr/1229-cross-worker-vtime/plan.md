---
status: DRAFT v1 — pending Codex hostile + Gemini adversarial review (with explicit mandate to push past Gemini PLAN-KILL if the kill rationale is empirically wrong)
issue: TBD (fresh issue, NOT a re-open of #1211)
phase: design proposal — substantive cross-worker fairness mechanism
prerequisites:
  - PR #1217 fairness contract (e1ec6b90) ✓
  - PR #1220 harness (bf87cf71) ✓ — provides the empirical gate this plan must clear
  - master 5cc09320 — even-flows recipe + sym-key + daemon-pin landed
  - #1211 PLAN-KILL archived under docs/per-5-tuple/path2-archive/
---

## 0. User-stated requirements (restated, cannot be relaxed)

- **No workload-side knobs.** Customer traffic uses whatever 5-tuples and
  rates it has. `--cport`/`-b`-style fixes are NOT acceptable.
- **The firewall must even out flows automatically.** Per-flow CoV at
  saturation should approach the structural ceiling regardless of
  RSS-imposed flow-distribution skew.
- **Reviewer pushback is welcome but not authoritative.** PLAN-KILL
  verdicts are reviewed adversarially by the operator; if a kill
  rationale is empirically wrong it does not block the work.

## 1. Why #1211 was killed and why the kill may be wrong

#1211 v2–v9 proposed AFD-style per-flow ECN-mark/drop with batched
ArcSwap-loaded summary state. Codex round-1–8 went PLAN-NEEDS-MAJOR
and ultimately got to a defensible design. Gemini PLAN-KILLed three
times citing:

1. **Cache-line bouncing in shared per-flow accounting.** Argument:
   per-packet RMW on a shared atomic across 6 workers saturates QPI.
2. **QSBR/RCU ordering complexity.** Argument: cross-worker shared
   state requires ordering guarantees that are hard to get right.
3. **ECN deployment reality.** Argument: TCP receivers must honor
   ECE; many don't on real internet.

#1220's harness now lets us empirically check (1) and (2). For (3),
this proposal sidesteps ECN entirely.

### 1.1 Cache-line bouncing rationale is empirically wrong for THIS architecture

AF_XDP zero-copy pins flow → queue → worker permanently. Codex's
post-v2 design — which Gemini did not engage with — has a critical
property:

> **Per-flow virtual-time accounting is single-writer.** Each
> per-flow vtime entry is owned by exactly one worker (the worker
> that owns the queue this flow's RSS-hash maps to). Other workers
> read this entry but never write to it.

Single-writer means:
- The vtime entry stays in the writer's L1 cache (no write-write
  bouncing).
- Reader workers fetch from L2/L3 if they need to compare; but reads
  don't cause cache-line invalidation on the writer.
- QPI traffic for the per-flow vtime table is bounded by the rate of
  per-flow entry CREATION (slow path on first packet), not per-packet
  updates.

Gemini's PLAN-KILL on cache-line was a generic warning about shared
mutable state; the actual cache behavior under AF_XDP queue-pinning is
fundamentally different. **PR #1220's empirical data quantified
inter-worker speed variance at 21% under no contention** — meaning
the WORKERS THEMSELVES are not bottlenecked on memory bandwidth.
Adding a per-flow vtime read cost (one cache line per cross-worker
comparison, batched at TX dispatch) would not move the 21% needle.

### 1.2 QSBR/RCU complexity is solvable via standard Rust pattern

`ArcSwap<HashMap<FiveTuple, AtomicU64>>` is the published-and-proven
RCU-equivalent for read-heavy maps in Rust. The pattern:

- Cold path (per-flow first packet): clone the HashMap, insert,
  `ArcSwap::store`. Old map drops when all readers finish.
- Hot path: `ArcSwap::load_full()` once per batch (NOT per packet),
  read multiple flow vtimes from the same loaded snapshot.
- TX dispatch: compare per-flow virtual time against the per-worker
  TX schedule.

PR #1188's worker-loop short-circuit (master 9d3faf02 + ArcSwap
optimization in PR #1201) demonstrates this exact pattern in
production.

### 1.3 ECN deployment is sidestepped

This proposal does NOT use ECN. Instead it uses **TCP RWND
manipulation on egress ACKs**. The firewall, as a stateful TCP
inspector, sees both directions of every flow. On the receiver →
sender ACK packet, the firewall rewrites the TCP window field
(and patches the L4 checksum delta). The sender's `cwnd` is bounded
by `min(cwnd, swnd)` where `swnd` is the receiver-advertised window.
Reduce `swnd` → sender backs off.

This is a well-known transparent-shaper technique used by F5 BIG-IP,
A10 Thunder, and other production firewalls. It does not require
sender or receiver opt-in. It is RFC 793 and RFC 7323 compliant
(window can shrink as long as it doesn't go negative or violate
SWS-rfc1122 prohibitions).

## 2. Mechanism — per-flow max-min fair share via cross-worker vtime + RWND

### 2.1 Per-flow virtual-time table

```rust
// userspace-dp/src/afxdp/fairness/mod.rs (NEW)

pub(crate) struct PerFlowVtime {
    bytes_served: AtomicU64,  // monotonic, single writer = owning worker
    last_update_ns: AtomicU64, // for drift / stale detection
    owner_worker: u32,         // which worker owns this entry
}

pub(crate) struct CrossWorkerFairness {
    // ArcSwap'd map: cold-path inserts replace the inner Arc; hot path
    // reads via load_full() once per batch.
    flow_table: ArcSwap<FxHashMap<FiveTuple, PerFlowVtime>>,
    // Per-worker view: what's MY worker's median per-flow byte-rate
    // among my owned flows. Computed at the umem debug-publish tick.
    per_worker_target_rate: [AtomicU64; MAX_WORKERS],
}
```

### 2.2 Per-batch fairness check at TX dispatch

```rust
// On TX dispatch in afxdp/tx/dispatch.rs
let snapshot = fairness.flow_table.load_full();  // 1 ArcSwap read per batch
for tx_pkt in tx_batch.iter() {
    let key = tx_pkt.flow_key();
    if let Some(entry) = snapshot.get(&key) {
        let my_vtime = entry.bytes_served.load(Relaxed);
        // Compare to global median (precomputed): if I'm > 10% ahead,
        // mark this flow as "throttle candidate".
        if my_vtime > global_median * 110 / 100 {
            tx_pkt.mark_throttle();
        }
    }
}
```

### 2.3 RWND throttle on ACK egress

```rust
// On ACK packet egress (per-packet, owner worker)
if flow.throttle_armed {
    let target_rwnd = compute_rwnd_for_target_rate(flow.target_rate);
    rewrite_tcp_window(pkt, target_rwnd);
    patch_tcp_checksum_delta(pkt);
}
```

`compute_rwnd_for_target_rate`: BDP = target_rate × RTT. RWND in
bytes is `BDP / WS` where `WS` is the window scaling factor (already
in flow state). For target_rate = global_median_per_flow_rate,
RWND = (median_rate × RTT_estimate) / WS.

RTT estimate: from the existing TCP conntrack timestamp tracking.

### 2.4 Cross-worker coordination

The per-worker target-rate publication tick (~65 ms) updates
`per_worker_target_rate[N]` with the median per-flow byte-rate
observed by that worker. Other workers read the array (single
read, 6 entries = 48 bytes, fits in one cache line) and compute
the global median.

**No per-packet cross-worker write.** All cross-worker reads are
to the small fixed-size array, not the per-flow table.

The per-flow table is updated only by:
- The owning worker's TX path (per-packet bytes_served increment).
- Flow eviction (cold-path slow tick).

## 3. Performance budget

| Item | Per-packet cost | Per-batch cost | Per-tick cost |
|---|---|---|---|
| TX-side vtime increment (own flow) | 1 atomic_add (cached) | 0 | 0 |
| Cross-worker target-rate read | 0 | 1 atomic_load × 6 | 0 |
| Median computation | 0 | 1 quickselect_6 | 0 |
| RWND rewrite (throttled flows only) | 1 16-bit write + 1 csum patch | 0 | 0 |
| ArcSwap snapshot | 0 | 1 load_full() | 0 |
| Slow-path: insert new flow | 0 | 0 | 1 clone + ArcSwap::store |

Hot-path cost: ~5 ns per-packet for non-throttled flows (just the
local atomic_add); ~30 ns for throttled flows (atomic_add +
RWND/csum on egress ACKs only).

Comparable to the AFD ECN proposal's budget; lower in practice
because no per-flow ECN lookup table.

## 4. Race surfaces

- **Per-flow vtime read by non-owning worker**: read can be stale by
  one update (not torn — u64 atomic_load). Acceptable; median is
  approximate.
- **Map replacement during read**: ArcSwap handles via Arc refcount.
  Reader holds Arc until deref dropped.
- **First-packet flow insert**: cold path. Slow tick or first-packet
  dispatch under a per-worker mutex. Bounded race: a flow could be
  inserted twice (both workers see "absent"); de-dup via `entry().or_insert()`.
- **RWND rewrite on TX-direction ACK**: ACK is RX from server's
  perspective, TX from firewall's perspective. The firewall sees
  it as ingress on WAN-binding; egress on LAN-binding. Per-flow state
  is on LAN-binding's owner worker.

## 5. Why this is feasible NOW (vs #1211 v9)

1. **Empirical evidence**: PR #1220's harness measured the inter-
   worker variance at 21%. AFD ECN's PLAN-KILL on cache-line was a
   prediction; the measurement now bounds the actual cost we're
   working against.
2. **Single-writer pattern**: codified above. Gemini's cache-line
   objection was about generic shared-mutable state, not the
   AF_XDP-pinned-queue pattern.
3. **RWND not ECN**: the deployment-reality kill point doesn't apply
   to RWND manipulation. Industry-standard technique.
4. **Smaller surface**: this is a TX-side enhancement to an existing
   path, not a full per-flow rolling-window scheduler rewrite.

## 6. Out of scope (this plan)

- Active measurement of RTT (use existing conntrack-timestamp delta).
- Cwnd manipulation directly (RWND only — TCP cwnd reacts).
- Per-class fairness coordination with CoS shaper. The per-flow
  fairness operates within a single forwarding class. Cross-class
  interactions are the existing CoS scheduler's job.
- ECN-marking as a fallback. If RWND fails for a flow (e.g.
  large-MSS bulk transfers don't honor RWND quickly), the flow is
  best-effort; no fallback drop.

## 7. Acceptance criteria — empirical

The mechanism is acceptance-passing iff, on the loss userspace
cluster (master + this PR):

- **Workload**: `iperf3 -c <target> -P 12 -t 90 -p 5205 -R` (the
  user's exact command, no `--cport`, no `-b`, no other flags).
- **Pre-mechanism baseline**: per-flow CoV ≥ 0.50 (current state
  per the user's screen capture earlier in this thread: 478 →
  3132 Mbps, CoV ≈ 0.6).
- **Post-mechanism**: per-flow CoV ≤ Cstruct + 0.10 where Cstruct
  is computed per the contract from #1217. (Looser than the
  contract's 0.05 because RWND is approximate.)
- **No aggregate regression**: aggregate throughput within ±5% of
  pre-mechanism aggregate.

## 8. Risks

- **Pathological RWND interaction with TCP_NODELAY / small writes**:
  RWND throttling primarily affects bulk transfers. For small-write
  flows, cwnd is the constraint and RWND has no effect. Acceptable
  scope: this mechanism targets the saturation case; mouse flows
  are unaffected.
- **TCP receivers with broken window-update logic**: rare but
  exists. The CWND-based AIMD provides a safety net (sender doesn't
  fully trust RWND).
- **Reviewer PLAN-KILL on novel-mechanism grounds**: Codex/Gemini
  may push back on the RWND novelty. **Plan: respond with industry
  precedent (F5, A10) and the empirical data from PR #1220.**

## 9. Open questions for adversarial review

1. Is the single-writer per-flow vtime claim actually true in the
   userspace-dp architecture? Specifically, can the same flow's
   packets ever arrive on two different workers (e.g. during a
   binding rebind, or a brief RSS reconfiguration)?
2. Is `ArcSwap<FxHashMap>` actually the right structure? Per-flow
   inserts are infrequent but at multi-megaflow scale the clone-
   on-write cost grows. Should we use a sharded Mutex<HashMap>
   instead?
3. Is RWND throttling effective at the Mbps scale we care about
   (1–5 Gbps per flow)? Worst case: a flow with cwnd = 4 MB
   already in flight when RWND drops to 1 MB — receiver may stall
   the sender for a full RTT before accepting more bytes. RTT in
   the lab is ≪1 ms so this is ≪1 ms hiccup.
4. What's the RTT estimate accuracy? If the timestamp-delta
   estimate is off by 2× the BDP calculation is off by 2×, which
   over-or-under-throttles. Acceptable?
5. Are there fairness-violating workloads where this makes things
   WORSE? E.g. a single fat flow on an idle worker — RWND throttle
   would slow it without any benefit because no other flow on
   that worker is getting starved.

## 10. Methodology

- v1 plan committed.
- Triple-review: Codex hostile + Gemini adversarial in parallel.
- **Explicit mandate to operator**: if Gemini PLAN-KILLs again
  citing a rationale that contradicts §1's empirical data, the
  operator (psaab) reviews and overrides. The plan does not stall
  on a single PLAN-KILL.
- Iterate to PLAN-READY consensus or operator override.
- Implement in stages: (a) per-flow vtime table + reader path,
  (b) RWND rewrite on egress, (c) cross-worker target-rate
  publication.
- Validate on the harness with the user's exact command.
- If empirical CoV drops below 0.10 on iperf3 -P 12 -p 5205, ship.
- If it doesn't drop, the mechanism is wrong; document why and
  return to design.
