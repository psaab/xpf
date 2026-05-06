---
status: DRAFT v1 — pending adversarial plan review; PLAN-KILL is acceptable and likely if Gemini's cache-line-bouncing concern proves binding
issue: #1211
phase: research-only — no implementation in this plan; goal is reviewer convergence on whether ANY race-safe design is feasible on AF_XDP ZC architecture
prerequisites:
  - #1206 (CoSQueueRuntime split) merged as a1688792 ✓
  - PR #1217 (fairness-regimes contract) — independent; this plan does NOT block #1217 shipping
  - Convergent finding (Codex task-mounv6zx + task-mouozcic; Gemini task-mounvopl + task-mouozuvq): cross-worker re-routing is structurally unreachable on AF_XDP ZC; AFD ECN backpressure is the only remaining algorithmic lever, IF it can be made race-safe
---

## 1. Issue framing

Saturated-RSS-skewed regime per `docs/fairness-regimes.md`: per-flow
CoV currently 25-30% on iperf-c P=12 -R; this plan's goal is to
explore whether AFD/CSFQ-style **per-flow ECN/drop overlay** can
reduce that to ≤25% (matching saturated-balanced) by pushing TCP
senders to slow flows that exceed their global fair share.

Per the killed-approaches list:
- #836 shared HOL-finish-time → non-commutative
- #838 AFD-lite per-flow bytes-served → 4 race surfaces
- #1215 cross-worker shared per-bucket signal + stall → permanent
  deadlock + HoL + can't transfer hardware capacity
- #937 ingress XDP_REDIRECT → AF_XDP ZC queue-binding permanent
  per kernel `xsk_rcv_check()`

This plan must NOT replicate any of those patterns.

## 2. Honest scope/value framing

**Research plan, not an implementation plan.** Goal: reviewer
convergence on whether ANY race-safe AFD design is feasible on this
codebase's AF_XDP ZC architecture, given:

- Codex's strict constraints (per-worker writes only; epoch
  snapshots; no rollback coupling; no global hot-path period reset)
- Gemini's hostile critique (cross-worker shared state for AQM =
  cache-line bouncing nightmare; Path 2 is "as unviable as Option B")

If reviewers converge PLAN-KILL, the user has clear evidence to
accept Path 4 (the fairness-regimes contract at #1217) as the
steady-state product.

If reviewers converge PLAN-READY-with-constraints, multi-week
implementation plan follows.

**Value cap**: improve saturated-RSS-skewed CoV from 25-30% toward
≤25% on TCP-with-ECN traffic. Does NOT help on UDP, non-ECN-capable
TCP, or workloads where senders ignore congestion signals.

## 3. Mechanism — race-safe AFD with sharded estimators

### 3.1 Shape

Each shared_exact queue gets:

```rust
// userspace-dp/src/afxdp/cos/afd.rs (new module, plan-only)
pub(in crate::afxdp) struct AfdEstimatorShard {
    /// Single-writer per worker. Each worker increments only its
    /// own shard. Cross-worker reads are atomic + Relaxed; readers
    /// accept eventual consistency.
    served_bytes: [AtomicU64; AFD_BUCKETS],
}

#[repr(C, align(64))]
pub(in crate::afxdp) struct AfdShardCacheLine {
    shard: AfdEstimatorShard,
    _pad: [u8; PAD_TO_64],
}

pub(in crate::afxdp) struct AfdQueueState {
    /// One shard per worker servicing this queue. Each worker's
    /// shard is on its own cache line — no cross-worker writes
    /// to the same cache line ever.
    shards: Box<[AfdShardCacheLine]>,

    /// Epoch number incremented by the snapshot owner only.
    /// Workers read this to know which window summary is current.
    epoch: AtomicU64,

    /// Read-mostly published window summary. Single writer
    /// (snapshot owner / coordinator); many cross-worker readers.
    /// Updated via ArcSwap (RCU-style). Never written from hot
    /// path.
    published_summary: ArcSwap<AfdWindowSummary>,
}

pub(in crate::afxdp) struct AfdWindowSummary {
    /// Per-bucket fair share computed from prior window.
    fair_share_bytes_per_bucket: [u64; AFD_BUCKETS],

    /// Per-bucket aggregate served-bytes from prior window
    /// (sum across all worker shards).
    aggregate_served: [u64; AFD_BUCKETS],

    /// Window duration in ns (for rate computations).
    window_duration_ns: u64,

    /// Active flow-bucket count from prior window.
    active_buckets: u16,
}
```

### 3.2 Hot path — write-only own shard, read-only published summary

On every shaped-pop on a shared_exact queue:

```rust
// In cos/queue_ops/pop.rs, after the existing served_finish/vtime advance.
if let Some(afd) = ff.afd.as_ref() {
    let bucket = bucket_u16 as usize;
    let my_shard = &afd.shards[queue.v_min.worker_id as usize];
    // Single-writer — fetch_add on own shard only. No false sharing
    // because own shard is on its own cache line.
    my_shard.shard.served_bytes[bucket].fetch_add(item_len_u64, Ordering::Relaxed);

    // Read the published summary (Relaxed via ArcSwap load).
    // ArcSwap.load() is an atomic pointer load + refcount inc —
    // ~5 ns amortized. Re-using the loaded Arc across multiple
    // packets in a batch via Box-deref hoisting (see #1206
    // pattern) amortizes further.
    let summary = afd.published_summary.load();
    let fair_share = summary.fair_share_bytes_per_bucket[bucket];

    // Decide ECN-mark based on prior-window aggregate vs fair share.
    // No live cross-worker read; only the published summary.
    let aggregate_for_bucket = summary.aggregate_served[bucket];
    if aggregate_for_bucket > fair_share && cos_item_is_ect(&item) {
        cos_item_mark_ce(&mut item);
    }
    // Probabilistic drop for non-ECT only when severely over-share.
    if aggregate_for_bucket > fair_share.saturating_mul(2) && !cos_item_is_ect(&item) {
        // Drop; let TCP retransmit slower.
        return Drop;
    }
}
```

**Key properties:**
- **No cross-worker writes to the same cache line.** Each worker's
  shard is `#[repr(C, align(64))]` with padding; fetch_add on own
  shard never bounces.
- **No live cross-worker reads.** The hot path reads only
  `published_summary` (RCU-style; Arc pointer load + dereference).
  This is a **read-mostly** access; the published Arc is updated
  rarely (once per window, ~10ms) by a single writer.
- **No rollback.** The fetch_add is monotonic per-worker. Submit-
  failure restoration of items does NOT decrement the counter
  because the bytes were genuinely served by the time we got to
  the pop site (per #1215's failed analysis — actually, this is
  the same pitfall #1215 had; need to reconsider). **Open**: see
  §6 Q1.
- **No global period reset.** Each worker's shard accumulates
  monotonically. The snapshot-owner reads them, computes window
  delta, publishes summary, then RESETS the snapshot baseline (not
  the shard — workers don't see resets).

### 3.3 Cold path — snapshot owner

A single dedicated thread (or piggybacked on existing 1Hz
coordinator status poll):

```rust
fn afd_snapshot_window(afd: &AfdQueueState, prior: &AfdWindowSummary) -> AfdWindowSummary {
    let now_ns = clock_monotonic_ns();
    let window_duration_ns = now_ns - prior.window_end_ns;
    let mut aggregate = [0u64; AFD_BUCKETS];
    for shard in afd.shards.iter() {
        // Cross-cache-line read here. Slow path; happens at window
        // boundary (~10ms cadence). Not a hot-path concern.
        for b in 0..AFD_BUCKETS {
            aggregate[b] += shard.shard.served_bytes[b].load(Ordering::Relaxed);
        }
    }
    // Compute fair share from active-bucket count, deltas vs prior.
    let active_buckets = aggregate.iter().filter(|&&b| b > prior.aggregate_served[b]).count();
    let total_window_bytes = aggregate.iter().zip(prior.aggregate_served.iter())
        .map(|(a, p)| a.saturating_sub(*p)).sum::<u64>();
    let fair_share_per_bucket = if active_buckets > 0 {
        total_window_bytes / active_buckets as u64
    } else {
        u64::MAX  // no marking when idle
    };
    AfdWindowSummary {
        fair_share_bytes_per_bucket: [fair_share_per_bucket; AFD_BUCKETS],
        aggregate_served: aggregate,
        window_duration_ns,
        active_buckets: active_buckets as u16,
    }
}
```

Then `afd.published_summary.store(Arc::new(new_summary))`. ArcSwap
ensures the old Arc is dropped after no readers hold it (epoch GC).

### 3.4 Race surfaces (vs #838's 4 known)

| #838 surface | This plan's answer |
|---|---|
| **Period reset coherence** | NO PERIOD RESET on workers. Only the snapshot owner sees window boundaries; it just publishes a new summary (RCU). Workers never see resets — they accumulate monotonically. |
| **Fair-share denominator staleness** | Denominator (`active_buckets`) is computed by snapshot owner ONCE per window and baked into the published summary. Workers never compute it. Window-to-window staleness = window duration (~10ms); acceptable as we're targeting TCP-cwnd-scale fairness. |
| **Rollback semantics** | Not applicable — workers don't do AFD-related rollback. The submit-failure restoration of pending items is orthogonal: those bytes were served (counted) but didn't go on the wire. **OPEN**: this same pitfall killed #1215 (see §6 Q1). |
| **Batch-latency mismatch** | Both selector (per-pop ECN-mark decision) and accumulator (per-pop fetch_add) are per-pop. No batch-vs-packet mismatch. |

### 3.5 Cache-line analysis (vs Gemini's "concurrency nightmare" critique)

- `shards` array is `Box<[AfdShardCacheLine]>` — each shard is
  exactly 64 bytes aligned. Worker N writes only to `shards[N]`.
  No cross-worker write contention.
- `published_summary` is an `ArcSwap<AfdWindowSummary>`. Workers
  only call `.load()` on it (Arc refcount + pointer read). The
  refcount is on its own cache line (Arc internal layout).
- Refcount inc/dec on `.load()` IS a cross-cache-line write. **This
  is the residual cache-line bouncing concern.** Mitigations:
  - ArcSwap uses a hazard-pointer-style mechanism that avoids
    incrementing the refcount in the common case (refcount-free
    fast path).
  - If even the hazard-pointer cost is too high, the published
    summary can be a `Box<AfdWindowSummary>` swapped via raw
    `AtomicPtr` with epoch-based reclamation (crossbeam-epoch).
    More complex but zero refcount traffic.
- `epoch: AtomicU64` is a snapshot-owner-write, worker-read field.
  Could be the same cache line as ArcSwap's internal pointer (false
  sharing across snapshot vs hot path). Place on its own cache line
  via `#[repr(C, align(64))]`.

**Estimated cost per pop on shared_exact queue:**
- 1 atomic fetch_add on own cache line: ~5 ns (no contention)
- 1 ArcSwap.load() (hazard-pointer fast path): ~3-5 ns
- 1 array index read on the published summary: ~2 ns (likely L1
  cache hit for the working bucket)
- 1 conditional ECN-mark write on packet: ~5 ns
- **Total: ~15-20 ns added to the per-pop hot path**

**This is the budget question.** At 64-byte packets / 35 Mpps line
rate, the per-packet budget is ~28 ns — adding 15-20 ns is 50-70%
of budget consumed, which is too much for line-rate-PPS workloads.
At 1500-byte packets / ~2 Mpps line rate, the budget is ~480 ns and
15-20 ns is 3-4% — acceptable.

**xpf's actual workload is mostly large-packet TCP** (iperf-style),
NOT 64-byte-PPS small-packet flooding. Small-packet performance is
not in the saturated-RSS-skewed regime; it's in high-fan-in
(separate gate). So the budget analysis at 1500B/2Mpps is the
relevant one.

### 3.6 HA failover

- On role flip, the `AfdQueueState` is dropped with the queue and
  rebuilt fresh. New shards start at zero served_bytes; new
  published summary starts with `fair_share = u64::MAX` (no
  marking until first window completes).
- **No saturating_sub underflow risk** because we never compute
  byte-rate diffs from old vs new values — only the snapshot owner
  computes deltas, and on a fresh queue the prior summary is the
  zero-init one.

### 3.7 Out-of-scope clarifications

- **Owner-local-exact queues**: NOT covered. AFD applies only to
  shared_exact queues where cross-worker fairness matters.
- **Best-effort queues**: NOT covered. Best-effort fairness is
  driven by single-FIFO drain order; AFD adds nothing.
- **UDP / non-ECN-capable**: AFD's ECN-mark path is a no-op; the
  probabilistic drop path applies but TCP's ECN response is the
  primary mechanism, so UDP gets only the drop side. Document this
  limitation.

## 4. Concrete prototype scope (if reviewers PLAN-READY)

A separate plan-and-PR after this plan is approved would deliver:

1. New module `userspace-dp/src/afxdp/cos/afd.rs` (~400 LOC).
2. Hook into `cos/queue_ops/pop.rs` after the existing vtime
   advance — single ECN-mark site.
3. Snapshot owner thread piggybacked on existing coordinator
   1Hz status poll, OR as a new dedicated 100Hz thread (window
   boundary cadence TBD by §6 Q3).
4. `AfdQueueState` allocated alongside `vtime_floor` and
   `flow_fair_state` at queue promotion time.
5. Feature flag (off by default) to enable AFD per shared_exact
   queue.
6. Telemetry: per-bucket marks, drops, fair-share-window — pin to
   #1209 telemetry double-buffer.

## 5. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression on FIFO/owner-local | NONE | Code path unchanged |
| Behavioral regression on shared_exact aggregate | LOW-MED | ECN marks should not reduce TCP throughput on ECN-capable senders if marks are accurate; UDP probabilistic drops will reduce throughput in over-share regime by design |
| Hot-path perf cost | MED | ~15-20 ns added per shaped-pop; acceptable at 1500B/2Mpps but not at 64B/35Mpps |
| Race-safety on shared atomics | LOW | Single-writer shards on own cache lines; published summary via RCU; no rollback |
| Cache-line bouncing | LOW-MED | ArcSwap hazard-pointer fast path mitigates; if measured high, fall back to crossbeam-epoch |
| HA failover | LOW | Fresh AfdQueueState on role flip; no underflow arithmetic |
| TCP receiver ECN response in production | UNKNOWN | Depends on receiver kernel + ECN-deployment status. Modern Linux honors ECN; some legacy stacks ignore it |

## 6. Open questions for adversarial review

1. **Submit-failure pitfall (same as #1215)**: when a worker pops a
   packet, fetch_adds served_bytes, then submit fails and the
   packet is restored to the queue, does the served_bytes counter
   over-state served work? §3.4 claims "not applicable" but Codex
   round-2 on #1215 specifically called this out as wrong reasoning.
   How does this plan actually avoid the same pitfall?

2. **Cache-line bouncing on ArcSwap**: Gemini's #937 review called
   cross-worker shared state for AQM a "concurrency nightmare." Is
   ArcSwap's hazard-pointer fast path actually low-overhead enough,
   or does crossbeam-epoch need to be the baseline?

3. **Window cadence**: 10ms (~100Hz) snapshot owner publishes —
   is this fast enough to react to TCP-burst dynamics, or too fast
   (causing window-boundary noise)? At ~100ms (~10Hz) we react
   slowly; at ~1ms (~1000Hz) the snapshot read itself becomes a
   per-cache-line cost on every shard. Where's the sweet spot?

4. **TCP-with-ECN deployment reality**: in 2026, what fraction of
   TCP senders honor CE marks? If <50%, the ECN side is ineffective
   and only the probabilistic drop side fires, hurting TCP via
   actual loss instead of the cwnd response.

5. **Bucket aggregation across shards**: §3.4 says
   `aggregate[b] = sum_over_shards(shard.served_bytes[b])`. With
   8 workers × AFD_BUCKETS buckets, that's 8 × N atomic loads per
   window. At AFD_BUCKETS = 4096 (matching COS_FLOW_FAIR_BUCKETS),
   that's 32K loads per window. At 10ms cadence, that's 3.2M
   loads/sec — uses ~16MB/s memory bandwidth. Acceptable?

6. **What if measurement shows ≤25% saturated-RSS-skewed gate is
   STILL not closed by AFD**? The fairness-regimes contract
   already accepts saturated-RSS-skewed at ≤30%. If AFD only
   moves it from 28% to 27%, was the multi-week effort worth it?
   At what improvement threshold should we ship vs decline?

7. **Should this plan include an explicit measurement-first
   gate** like #900 / Codex Path 0? "Build the deterministic
   RSS-skew fixture first, measure CoV at every stage, only ship
   AFD if it provably closes the gap"?

## 7. Verdict request

PLAN-READY → plan a separate prototype implementation PR.
PLAN-NEEDS-MINOR → tighten cache-line analysis or window cadence.
PLAN-NEEDS-MAJOR → restructure (e.g., make epoch-based reclamation
the baseline, not a fallback; or pivot to a different snapshot
mechanism).
PLAN-KILL → §6 Q2 is fundamentally unsolvable on this codebase
(cache-line bouncing dominates regardless of design); OR §6 Q4 is
'<50% ECN' so the TCP side is too weak to matter; OR §6 Q1 (submit-
failure pitfall) cannot be cleanly avoided. Acceptable verdict; in
that case the fairness-regimes contract (PR #1217) is the
steady-state product.
